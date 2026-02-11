//! Bytecode virtual machine for executing compiled Python code.
//!
//! The VM uses a stack-based execution model with an operand stack for computation
//! and a call stack for function frames. Each frame owns its instruction pointer (IP).

mod async_exec;
mod attr;
mod binary;
mod call;
mod collections;
mod compare;
mod exceptions;
mod format;
mod scheduler;

use std::cmp::Ordering;

use call::CallResult;
use scheduler::Scheduler;

use security_compass_meta::Metadata;

use crate::{
    MontyObject,
    args::ArgValues,
    asyncio::{CallId, TaskId},
    bytecode::{code::Code, op::Opcode},
    exception_private::{ExcType, RunError, RunResult, SimpleException},
    heap::{ContainsHeap, Heap, HeapData, HeapId},
    intern::{ExtFunctionId, FunctionId, Interns, StringId},
    io::PrintWriter,
    modules::BuiltinModule,
    namespace::{GLOBAL_NS_IDX, NamespaceId, Namespaces},
    os::OsFunction,
    parse::CodeRange,
    resource::ResourceTracker,
    types::{LongInt, MontyIter, PyTrait, iter::advance_on_heap},
    value::{BitwiseOp, Value},
};

/// Trait for checking branch conditions against metadata policy.
///
/// Implemented by the interpreter layer (Phase 5) to enforce that
/// untrusted metadata cannot influence control flow.
pub trait BranchChecker: Send {
    /// Check if branching is allowed given the condition's metadata.
    ///
    /// Returns `Ok(())` if branching is allowed, or `Err(MontyException)` if denied.
    fn check(&self, condition_meta: &Metadata) -> Result<(), crate::MontyException>;
}

/// Result of executing Await opcode.
///
/// Indicates what the VM should do after awaiting a value:
/// - `ValueReady`: the awaited value resolved immediately, push it
/// - `FramePushed`: a new frame was pushed for coroutine execution
/// - `Yield`: all tasks blocked, yield to caller with pending futures
enum AwaitResult {
    /// The awaited value resolved immediately (e.g., resolved ExternalFuture).
    ValueReady(Value),
    /// A new frame was pushed to execute a coroutine.
    FramePushed,
    /// All tasks are blocked - yield to caller with pending futures.
    Yield(Vec<CallId>),
}

/// Tries an operation and handles exceptions, reloading cached frame state.
///
/// Use this in the main run loop where `cached_frame`
/// are used. After catching an exception, reloads the cache since the handler
/// may be in a different frame.
macro_rules! try_catch_sync {
    ($self:expr, $cached_frame:ident, $expr:expr) => {
        if let Err(e) = $expr {
            if let Some(result) = $self.handle_exception(e) {
                return Err(result);
            }
            // Exception was caught - handler may be in different frame, reload cache
            reload_cache!($self, $cached_frame);
            continue;
        }
    };
}

/// Handles an exception and reloads cached frame state if caught.
///
/// Use this in the main run loop where `cached_frame`
/// are used. After catching an exception, reloads the cache since the handler
/// may be in a different frame.
///
/// Wrapped in a block to allow use in match arm expressions.
macro_rules! catch_sync {
    ($self:expr, $cached_frame:ident, $err:expr) => {{
        if let Some(result) = $self.handle_exception($err) {
            return Err(result);
        }
        // Exception was caught - handler may be in different frame, reload cache
        reload_cache!($self, $cached_frame);
        continue;
    }};
}

/// Fetches a byte from bytecode using cached code/ip, advancing ip.
///
/// Used in the run loop for fast operand fetching without frame access.
macro_rules! fetch_byte {
    ($cached_frame:expr) => {{
        let byte = $cached_frame.code.bytecode()[$cached_frame.ip];
        $cached_frame.ip += 1;
        byte
    }};
}

/// Fetches a u8 operand using cached code/ip.
macro_rules! fetch_u8 {
    ($cached_frame:expr) => {
        fetch_byte!($cached_frame)
    };
}

/// Fetches an i8 operand using cached code/ip.
macro_rules! fetch_i8 {
    ($cached_frame:expr) => {{ i8::from_ne_bytes([fetch_byte!($cached_frame)]) }};
}

/// Fetches a u16 operand (little-endian) using cached code/ip.
macro_rules! fetch_u16 {
    ($cached_frame:expr) => {{
        let lo = $cached_frame.code.bytecode()[$cached_frame.ip];
        let hi = $cached_frame.code.bytecode()[$cached_frame.ip + 1];
        $cached_frame.ip += 2;
        u16::from_le_bytes([lo, hi])
    }};
}

/// Fetches an i16 operand (little-endian) using cached code/ip.
macro_rules! fetch_i16 {
    ($cached_frame:expr) => {{
        let lo = $cached_frame.code.bytecode()[$cached_frame.ip];
        let hi = $cached_frame.code.bytecode()[$cached_frame.ip + 1];
        $cached_frame.ip += 2;
        i16::from_le_bytes([lo, hi])
    }};
}

/// Reloads cached frame state from the current frame.
///
/// Call this after any operation that modifies the frame stack (calls, returns,
/// exception handling).
macro_rules! reload_cache {
    ($self:expr, $cached_frame:ident) => {{
        $cached_frame = $self.new_cached_frame();
    }};
}

/// Applies a relative jump offset to the cached IP.
///
/// Uses checked arithmetic to safely compute the new IP, panicking if the
/// jump would result in a negative or overflowing instruction pointer.
macro_rules! jump_relative {
    ($ip:expr, $offset:expr) => {{
        let ip_i64 = i64::try_from($ip).expect("instruction pointer exceeds i64");
        let new_ip = ip_i64 + i64::from($offset);
        $ip = usize::try_from(new_ip).expect("jump resulted in negative or overflowing IP");
    }};
}

/// Handles the result of a call operation that returns `CallResult`.
///
/// This macro eliminates the repetitive pattern of matching on `CallResult`
/// variants that appears in LoadAttr, CallFunction, CallFunctionKw, CallAttr,
/// CallAttrKw, and CallFunctionExtended opcodes.
///
/// Actions taken for each variant:
/// - `Push(value)`: Push the value onto the stack
/// - `FramePushed`: Reload the cached frame (a new frame was pushed)
/// - `External(ext_id, args)`: Return `FrameExit::ExternalCall` to yield to host
/// - `OsCall(func, args)`: Return `FrameExit::OsCall` to yield to host
/// - `Err(err)`: Handle the exception via `catch_sync!`
macro_rules! handle_call_result {
    ($self:expr, $cached_frame:ident, $result:expr) => {
        match $result {
            Ok(CallResult::Push(result)) => {
                // Sync metadata stack after call consumed values internally
                $self.stack_meta.truncate($self.stack.len());
                $self.push(result);
                $self.push_meta(Metadata::default());
            }
            Ok(CallResult::FramePushed) => {
                // For defined function calls, metadata is handled in the callee's namespace
                $self.stack_meta.truncate($self.stack.len());
                reload_cache!($self, $cached_frame);
            }
            Ok(CallResult::External(ext_id, args)) => {
                // Extract arg metadata from surplus BEFORE truncation
                let args_meta = $self.extract_args_meta_from_surplus(args.count());
                $self.stack_meta.truncate($self.stack.len());
                let call_id = $self.allocate_call_id();
                // Sync cached IP back to frame before snapshot for resume
                $self.current_frame_mut().ip = $cached_frame.ip;
                return Ok(FrameExit::ExternalCall {
                    ext_function_id: ext_id,
                    args,
                    args_meta,
                    call_id,
                });
            }
            Ok(CallResult::OsCall(func, args)) => {
                // Extract arg metadata from surplus BEFORE truncation
                let args_meta = $self.extract_args_meta_from_surplus(args.count());
                $self.stack_meta.truncate($self.stack.len());
                let call_id = $self.allocate_call_id();
                // Sync cached IP back to frame before snapshot for resume
                $self.current_frame_mut().ip = $cached_frame.ip;
                return Ok(FrameExit::OsCall {
                    function: func,
                    args,
                    args_meta,
                    call_id,
                });
            }
            Err(err) => {
                $self.stack_meta.truncate($self.stack.len());
                catch_sync!($self, $cached_frame, err);
            }
        }
    };
}

/// Result of VM execution.
pub enum FrameExit {
    /// Execution completed successfully with a return value and its metadata.
    Return(Value, Metadata),

    /// Execution paused for an external function call.
    ///
    /// The caller should execute the external function and call `resume()`
    /// with the result. The `call_id` allows the host to use async resolution
    /// by calling `run_pending()` instead of `run(result)`.
    ExternalCall {
        /// ID of the external function to call.
        ext_function_id: ExtFunctionId,
        /// Arguments for the external function (includes both positional and keyword args).
        args: ArgValues,
        /// Metadata for each positional argument, extracted from the VM's parallel metadata stack.
        args_meta: Vec<Metadata>,
        /// Unique ID for this call, used for async correlation.
        call_id: CallId,
    },

    /// Execution paused for an os function call.
    ///
    /// The caller should execute a function corresponding to the `os_call` and call `resume()`
    /// with the result. The `call_id` allows the host to use async resolution
    /// by calling `run_pending()` instead of `run(result)`.
    OsCall {
        /// ID of the os function to call.
        function: OsFunction,
        /// Arguments for the external function (includes both positional and keyword args).
        args: ArgValues,
        /// Metadata for each positional argument, extracted from the VM's parallel metadata stack.
        args_meta: Vec<Metadata>,
        /// Unique ID for this call, used for async correlation.
        call_id: CallId,
    },

    /// All tasks are blocked waiting for external futures to resolve.
    ///
    /// The caller must resolve the pending CallIds before calling `resume()`.
    /// This happens when await is called on an ExternalFuture that hasn't
    /// been resolved yet, and there are no other ready tasks to switch to.
    ResolveFutures(Vec<CallId>),
}

/// A single function activation record.
///
/// Each frame represents one level in the call stack and owns its own
/// instruction pointer. This design avoids sync bugs on call/return.
#[derive(Debug)]
pub struct CallFrame<'code> {
    /// Bytecode being executed.
    code: &'code Code,

    /// Instruction pointer within this frame's bytecode.
    ip: usize,

    /// Base index into operand stack for this frame.
    ///
    /// Used to identify where this frame's stack region begins.
    stack_base: usize,

    /// Namespace index for this frame's locals.
    namespace_idx: NamespaceId,

    /// Function ID (for tracebacks). None for module-level code.
    function_id: Option<FunctionId>,

    /// Captured cells for closures.
    cells: Vec<HeapId>,

    /// Call site position (for tracebacks).
    call_position: Option<CodeRange>,
}

impl<'code> CallFrame<'code> {
    /// Creates a new call frame for module-level code.
    pub fn new_module(code: &'code Code, namespace_idx: NamespaceId) -> Self {
        Self {
            code,
            ip: 0,
            stack_base: 0,
            namespace_idx,
            function_id: None,
            cells: Vec::new(),
            call_position: None,
        }
    }

    /// Creates a new call frame for a function call.
    pub fn new_function(
        code: &'code Code,
        stack_base: usize,
        namespace_idx: NamespaceId,
        function_id: FunctionId,
        cells: Vec<HeapId>,
        call_position: Option<CodeRange>,
    ) -> Self {
        Self {
            code,
            ip: 0,
            stack_base,
            namespace_idx,
            function_id: Some(function_id),
            cells,
            call_position,
        }
    }
}

/// Cached state of the VM derived from the current frame as an optimization
#[derive(Debug, Copy, Clone)]
pub struct CachedFrame<'code> {
    /// Bytecode being executed.
    code: &'code Code,

    /// Instruction pointer within this frame's bytecode.
    ip: usize,

    /// Namespace index for this frame's locals.
    namespace_idx: NamespaceId,
}

impl<'code> From<&CallFrame<'code>> for CachedFrame<'code> {
    fn from(frame: &CallFrame<'code>) -> Self {
        Self {
            code: frame.code,
            ip: frame.ip,
            namespace_idx: frame.namespace_idx,
        }
    }
}

/// Serializable representation of a call frame.
///
/// Cannot store `&Code` (a reference) - instead stores `FunctionId` to look up
/// the pre-compiled Code object on resume. Module-level code uses `None`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerializedFrame {
    /// Which function's code this frame executes (None = module-level).
    function_id: Option<FunctionId>,

    /// Instruction pointer within this frame's bytecode.
    ip: usize,

    /// Base index into operand stack for this frame's locals.
    stack_base: usize,

    /// Namespace index for this frame's locals.
    namespace_idx: NamespaceId,

    /// Captured cells for closures (HeapIds remain valid after heap deserialization).
    cells: Vec<HeapId>,

    /// Call site position (for tracebacks).
    call_position: Option<CodeRange>,
}

impl CallFrame<'_> {
    /// Converts this frame to a serializable representation.
    fn serialize(&self) -> SerializedFrame {
        SerializedFrame {
            function_id: self.function_id,
            ip: self.ip,
            stack_base: self.stack_base,
            namespace_idx: self.namespace_idx,
            cells: self.cells.clone(),
            call_position: self.call_position,
        }
    }
}

/// VM state for pause/resume at external function calls.
///
/// **Ownership:** This struct OWNS the values (refcounts were already incremented).
/// Must be used with the serialized Heap - HeapId values are indices into that heap.
///
/// **Usage:** When the VM pauses for an external call, call `into_snapshot()` to
/// create this snapshot. The snapshot can be serialized and stored. On resume,
/// use `restore()` to reconstruct the VM and continue execution.
///
/// Note: This struct does not implement `Clone` because `Value` uses manual
/// reference counting. Snapshots transfer ownership - they are not copied.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct VMSnapshot {
    /// Operand stack (may contain Value::Ref(HeapId) pointing to heap).
    stack: Vec<Value>,

    /// Parallel metadata for the operand stack.
    stack_meta: Vec<Metadata>,

    /// Call frames (serializable form - stores FunctionId, not &Code).
    frames: Vec<SerializedFrame>,

    /// Stack of exceptions being handled for nested except blocks.
    ///
    /// When entering an except handler, the exception is pushed onto this stack.
    /// When exiting via `ClearException`, the top is popped. This allows nested
    /// except handlers to restore the outer exception context.
    exception_stack: Vec<Value>,

    /// IP of the instruction that caused the pause (for exception handling).
    instruction_ip: usize,

    /// Counter for external call IDs when scheduler is not initialized.
    next_call_id: u32,

    /// Scheduler state for async execution (optional).
    ///
    /// Contains all task state, pending calls, and resolved futures.
    /// This enables async execution to be paused and resumed across host calls.
    /// None if no async operations have been performed yet.
    scheduler: Option<Scheduler>,
}

// ============================================================================
// Virtual Machine
// ============================================================================

/// The bytecode virtual machine.
///
/// Executes compiled bytecode using a stack-based execution model.
/// The instruction pointer (IP) lives in each `CallFrame`, not here,
/// to avoid sync bugs on call/return.
pub struct VM<'a, T: ResourceTracker, P: PrintWriter> {
    /// Operand stack - values being computed.
    stack: Vec<Value>,

    /// Parallel metadata for the operand stack.
    /// Invariant: stack_meta.len() == stack.len() at every instruction boundary.
    stack_meta: Vec<Metadata>,

    /// Call stack - function frames (each frame has its own IP).
    frames: Vec<CallFrame<'a>>,

    /// Heap for reference-counted objects.
    heap: &'a mut Heap<T>,

    /// Namespace stack for variable storage.
    namespaces: &'a mut Namespaces,

    /// Interned strings/bytes.
    interns: &'a Interns,

    /// Print output writer.
    print_writer: &'a mut P,

    /// Stack of exceptions being handled for nested except blocks.
    ///
    /// Used by bare `raise` to re-raise the current exception.
    /// When entering an except handler, the exception is pushed onto this stack.
    /// When exiting via `ClearException`, the top is popped. This allows nested
    /// except handlers to restore the outer exception context.
    exception_stack: Vec<Value>,

    /// IP of the instruction being executed (for exception table lookup).
    ///
    /// Updated at the start of each instruction before operands are fetched.
    /// This allows us to find the correct exception handler when an error occurs.
    instruction_ip: usize,

    /// Counter for external call IDs when scheduler is not initialized.
    ///
    /// Used by `allocate_call_id()` when no scheduler exists (sync code paths).
    /// When a scheduler is created, this counter is transferred to it.
    next_call_id: u32,

    /// Scheduler for async task management (lazy - only created when needed).
    ///
    /// Manages concurrent tasks, external call tracking, and task switching.
    /// Created lazily on first async operation to avoid allocations for sync code.
    scheduler: Option<Scheduler>,

    /// Optional branch checker for policy enforcement at conditional jumps.
    /// Called at JumpIfTrue/JumpIfFalse to verify metadata policy compliance.
    branch_checker: Option<Box<dyn BranchChecker>>,

    /// Module-level code (for restoring main task frames).
    ///
    /// Stored here because the main task's frames have `function_id: None` and
    /// need a reference to the module code when being restored after task switching.
    module_code: Option<&'a Code>,
}

impl<'a, T: ResourceTracker, P: PrintWriter> VM<'a, T, P> {
    /// Creates a new VM with the given runtime context.
    pub fn new(
        heap: &'a mut Heap<T>,
        namespaces: &'a mut Namespaces,
        interns: &'a Interns,
        print_writer: &'a mut P,
    ) -> Self {
        Self {
            stack: Vec::with_capacity(64),
            stack_meta: Vec::with_capacity(64),
            frames: Vec::with_capacity(16),
            heap,
            namespaces,
            interns,
            print_writer,
            exception_stack: Vec::new(),
            instruction_ip: 0,
            next_call_id: 0,
            scheduler: None, // Lazy - no allocation for sync code
            branch_checker: None,
            module_code: None,
        }
    }

    /// Reconstructs a VM from a snapshot.
    ///
    /// The heap and namespaces must already be deserialized. `FunctionId` values
    /// in frames are used to look up pre-compiled `Code` objects from the `Interns`.
    /// The `module_code` is used for frames with `function_id = None`.
    ///
    /// # Arguments
    /// * `snapshot` - The VM snapshot to restore
    /// * `module_code` - Compiled module code (for frames with function_id = None)
    /// * `heap` - The deserialized heap
    /// * `namespaces` - The deserialized namespaces
    /// * `interns` - Interns for looking up function code
    /// * `print_writer` - Writer for print output
    pub fn restore(
        snapshot: VMSnapshot,
        module_code: &'a Code,
        heap: &'a mut Heap<T>,
        namespaces: &'a mut Namespaces,
        interns: &'a Interns,
        print_writer: &'a mut P,
    ) -> Self {
        // Reconstruct call frames from serialized form
        let frames = snapshot
            .frames
            .into_iter()
            .map(|sf| {
                let code = match sf.function_id {
                    Some(func_id) => &interns.get_function(func_id).code,
                    None => module_code,
                };
                CallFrame {
                    code,
                    ip: sf.ip,
                    stack_base: sf.stack_base,
                    namespace_idx: sf.namespace_idx,
                    function_id: sf.function_id,
                    cells: sf.cells,
                    call_position: sf.call_position,
                }
            })
            .collect();

        Self {
            stack: snapshot.stack,
            stack_meta: snapshot.stack_meta,
            frames,
            heap,
            namespaces,
            interns,
            print_writer,
            exception_stack: snapshot.exception_stack,
            instruction_ip: snapshot.instruction_ip,
            next_call_id: snapshot.next_call_id,
            scheduler: snapshot.scheduler,
            branch_checker: None, // Must be re-set by caller after restore
            module_code: Some(module_code),
        }
    }
    /// Consumes the VM and creates a snapshot for pause/resume if needed.
    pub fn check_snapshot(mut self, result: &RunResult<FrameExit>) -> Option<VMSnapshot> {
        if matches!(
            result,
            Ok(FrameExit::ExternalCall { .. } | FrameExit::OsCall { .. } | FrameExit::ResolveFutures(_))
        ) {
            Some(self.snapshot())
        } else {
            self.cleanup();
            None
        }
    }

    /// Consumes the VM and creates a snapshot for pause/resume.
    ///
    /// **Ownership transfer:** This method takes `self` by value, consuming the VM.
    /// The snapshot owns all Values (refcounts already correct from the live VM).
    /// The heap and namespaces must be serialized alongside this snapshot.
    ///
    /// This is NOT a clone - it's a transfer. After calling this, the original VM
    /// is gone and only the snapshot (+ serialized heap/namespaces) represents the state.
    pub fn snapshot(self) -> VMSnapshot {
        VMSnapshot {
            // Move values directly - no clone, no refcount increment needed
            // (the VM owned them, now the snapshot owns them)
            stack: self.stack,
            stack_meta: self.stack_meta,
            frames: self.frames.into_iter().map(|f| f.serialize()).collect(),
            exception_stack: self.exception_stack,
            instruction_ip: self.instruction_ip,
            next_call_id: self.next_call_id,
            scheduler: self.scheduler,
        }
    }

    /// Pushes an initial frame for module-level code and runs the VM.
    pub fn run_module(&mut self, code: &'a Code) -> Result<FrameExit, RunError> {
        // Store module code for restoring main task frames during task switching
        self.module_code = Some(code);
        self.frames.push(CallFrame::new_module(code, GLOBAL_NS_IDX));
        self.run()
    }

    /// Cleans up VM state before the VM is dropped.
    ///
    /// This method must be called before the VM goes out of scope to ensure
    /// proper reference counting cleanup for any exception values and scheduler state.
    pub fn cleanup(&mut self) {
        // Drop all exceptions in the exception stack
        for exc in self.exception_stack.drain(..) {
            exc.drop_with_heap(self.heap);
        }
        // Stack should be empty, but clean up just in case
        for value in self.stack.drain(..) {
            value.drop_with_heap(self.heap);
        }
        self.stack_meta.clear();
        // Clean up current frames (main module frame after return, or any remaining frames)
        self.cleanup_current_frames();
        // Clean up task frame namespaces (scheduler doesn't have access to namespaces)
        self.cleanup_all_task_frames();
        // Clean up scheduler state (task stacks, pending calls, resolved values)
        if let Some(scheduler) = &mut self.scheduler {
            scheduler.cleanup(self.heap);
        }
    }

    /// Cleans up frames stored in all scheduler tasks.
    ///
    /// Task frames reference namespaces and cells that need to be cleaned up
    /// before the VM is dropped. This is separate from `scheduler.cleanup()`
    /// because the scheduler doesn't have access to the VM's namespaces.
    fn cleanup_all_task_frames(&mut self) {
        let Some(scheduler) = &mut self.scheduler else {
            return;
        };
        // Clean up each task's saved frames
        for task_idx in 0..scheduler.task_count() {
            let task_id = TaskId::new(u32::try_from(task_idx).expect("task_idx exceeds u32"));
            let task = scheduler.get_task_mut(task_id);
            for frame in std::mem::take(&mut task.frames) {
                // Clean up cell references
                for cell_id in frame.cells {
                    self.heap.dec_ref(cell_id);
                }
                // Clean up the namespace (but not the global namespace)
                if frame.namespace_idx != GLOBAL_NS_IDX {
                    self.namespaces.drop_with_heap(frame.namespace_idx, self.heap);
                }
            }
        }
    }

    /// Allocates a new `CallId` for an external function call.
    ///
    /// Works with or without a scheduler. If a scheduler exists, delegates to it.
    /// Otherwise, uses the VM's `next_call_id` counter directly, avoiding
    /// scheduler creation overhead for synchronous external calls.
    fn allocate_call_id(&mut self) -> CallId {
        if let Some(scheduler) = &mut self.scheduler {
            scheduler.allocate_call_id()
        } else {
            let id = CallId::new(self.next_call_id);
            self.next_call_id += 1;
            id
        }
    }

    /// Returns true if we're on the main task (or no async at all).
    ///
    /// This is used to determine whether a `ReturnValue` at the last frame means
    /// module-level completion (return to host) or spawned task completion
    /// (handle task completion and switch).
    fn is_main_task(&self) -> bool {
        self.scheduler
            .as_ref()
            .is_none_or(|s| s.current_task_id().is_none_or(TaskId::is_main))
    }

    /// Main execution loop.
    ///
    /// Fetches opcodes from the current frame's bytecode and executes them.
    /// Returns when execution completes, an error occurs, or an external
    /// call is needed.
    ///
    /// Uses locally cached `code` and `ip` variables to avoid repeated
    /// `frames.last_mut().expect()` calls during operand fetching. The cache
    /// is reloaded after any operation that modifies the frame stack.
    pub fn run(&mut self) -> Result<FrameExit, RunError> {
        // Cache frame state locally to avoid repeated frames.last_mut() calls.
        // The Code reference has lifetime 'a (lives in Interns), independent of frame borrow.
        let mut cached_frame: CachedFrame<'a> = self.new_cached_frame();

        loop {
            // Check time limit and trigger GC if needed at each instruction.
            // For NoLimitTracker, these are inlined no-ops that compile away.
            self.heap.tracker_mut().check_time()?;

            if self.heap.should_gc() {
                // Sync IP before GC for safety
                self.current_frame_mut().ip = cached_frame.ip;
                self.run_gc();
            }

            // Track instruction IP for exception table lookup
            self.instruction_ip = cached_frame.ip;

            // Fetch opcode using cached values (no frame access)
            let opcode = {
                let byte = cached_frame.code.bytecode()[cached_frame.ip];
                cached_frame.ip += 1;
                Opcode::try_from(byte).expect("invalid opcode in bytecode")
            };

            match opcode {
                // ============================================================
                // Stack Operations
                // ============================================================
                Opcode::Pop => {
                    let value = self.pop();
                    let _meta = self.pop_meta();
                    value.drop_with_heap(self.heap);
                }
                Opcode::Dup => {
                    // Clone metadata for the duplicated value
                    let meta = self.peek_meta().clone();
                    // Copy without incrementing refcount first (avoids borrow conflict)
                    let value = self.peek().copy_for_extend();
                    // Now we can safely increment refcount and push
                    if let Value::Ref(id) = &value {
                        self.heap.inc_ref(*id);
                    }
                    self.push(value);
                    self.push_meta(meta);
                }
                Opcode::Rot2 => {
                    // Swap top two: [a, b] → [b, a]
                    let len = self.stack.len();
                    self.stack.swap(len - 1, len - 2);
                    let meta_len = self.stack_meta.len();
                    self.stack_meta.swap(meta_len - 1, meta_len - 2);
                }
                Opcode::Rot3 => {
                    // Rotate top three: [a, b, c] → [c, a, b]
                    // Uses in-place rotation without cloning
                    let len = self.stack.len();
                    // Move c out, then shift a→b→c, then put c at a's position
                    // Equivalent to: [..rest, a, b, c] → [..rest, c, a, b]
                    self.stack[len - 3..].rotate_right(1);
                    let meta_len = self.stack_meta.len();
                    self.stack_meta[meta_len - 3..].rotate_right(1);
                }
                // Constants & Literals
                Opcode::LoadConst => {
                    let idx = fetch_u16!(cached_frame);
                    // Copy without incrementing refcount first (avoids borrow conflict)
                    let value = cached_frame.code.constants().get(idx).copy_for_extend();
                    // Handle InternLongInt specially - convert to heap-allocated LongInt
                    if let Value::InternLongInt(long_int_id) = value {
                        let bi = self.interns.get_long_int(long_int_id).clone();
                        match LongInt::new(bi).into_value(self.heap) {
                            Ok(v) => {
                                self.push(v);
                                self.push_meta(Metadata::default());
                            }
                            Err(e) => catch_sync!(self, cached_frame, RunError::from(e)),
                        }
                    } else {
                        // Now we can safely increment refcount for Ref values
                        if let Value::Ref(id) = &value {
                            self.heap.inc_ref(*id);
                        }
                        self.push(value);
                        self.push_meta(Metadata::default());
                    }
                }
                Opcode::LoadNone => {
                    self.push(Value::None);
                    self.push_meta(Metadata::default());
                }
                Opcode::LoadTrue => {
                    self.push(Value::Bool(true));
                    self.push_meta(Metadata::default());
                }
                Opcode::LoadFalse => {
                    self.push(Value::Bool(false));
                    self.push_meta(Metadata::default());
                }
                Opcode::LoadSmallInt => {
                    let n = fetch_i8!(cached_frame);
                    self.push(Value::Int(i64::from(n)));
                    self.push_meta(Metadata::default());
                }
                // Variables - Specialized Local Loads (no operand)
                Opcode::LoadLocal0 => try_catch_sync!(self, cached_frame, self.load_local(&cached_frame, 0)),
                Opcode::LoadLocal1 => try_catch_sync!(self, cached_frame, self.load_local(&cached_frame, 1)),
                Opcode::LoadLocal2 => try_catch_sync!(self, cached_frame, self.load_local(&cached_frame, 2)),
                Opcode::LoadLocal3 => try_catch_sync!(self, cached_frame, self.load_local(&cached_frame, 3)),
                // Variables - General Local Operations
                Opcode::LoadLocal => {
                    let slot = u16::from(fetch_u8!(cached_frame));
                    try_catch_sync!(self, cached_frame, self.load_local(&cached_frame, slot));
                }
                Opcode::LoadLocalW => {
                    let slot = fetch_u16!(cached_frame);
                    try_catch_sync!(self, cached_frame, self.load_local(&cached_frame, slot));
                }
                Opcode::StoreLocal => {
                    let slot = u16::from(fetch_u8!(cached_frame));
                    self.store_local(&cached_frame, slot);
                }
                Opcode::StoreLocalW => {
                    let slot = fetch_u16!(cached_frame);
                    self.store_local(&cached_frame, slot);
                }
                Opcode::DeleteLocal => {
                    let slot = u16::from(fetch_u8!(cached_frame));
                    self.delete_local(&cached_frame, slot);
                }
                // Variables - Global Operations
                Opcode::LoadGlobal => {
                    let slot = fetch_u16!(cached_frame);
                    try_catch_sync!(self, cached_frame, self.load_global(slot));
                }
                Opcode::StoreGlobal => {
                    let slot = fetch_u16!(cached_frame);
                    self.store_global(slot);
                }
                // Variables - Cell Operations (closures)
                Opcode::LoadCell => {
                    let slot = fetch_u16!(cached_frame);
                    try_catch_sync!(self, cached_frame, self.load_cell(slot));
                }
                Opcode::StoreCell => {
                    let slot = fetch_u16!(cached_frame);
                    self.store_cell(slot);
                }
                // Binary Operations - route through exception handling for tracebacks
                Opcode::BinaryAdd => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_add());
                    self.push_meta(merged);
                }
                Opcode::BinarySub => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_sub());
                    self.push_meta(merged);
                }
                Opcode::BinaryMul => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_mult());
                    self.push_meta(merged);
                }
                Opcode::BinaryDiv => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_div());
                    self.push_meta(merged);
                }
                Opcode::BinaryFloorDiv => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_floordiv());
                    self.push_meta(merged);
                }
                Opcode::BinaryMod => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_mod());
                    self.push_meta(merged);
                }
                Opcode::BinaryPow => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_pow());
                    self.push_meta(merged);
                }
                // Bitwise operations - only work on integers
                Opcode::BinaryAnd => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_bitwise(BitwiseOp::And));
                    self.push_meta(merged);
                }
                Opcode::BinaryOr => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_bitwise(BitwiseOp::Or));
                    self.push_meta(merged);
                }
                Opcode::BinaryXor => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_bitwise(BitwiseOp::Xor));
                    self.push_meta(merged);
                }
                Opcode::BinaryLShift => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_bitwise(BitwiseOp::LShift));
                    self.push_meta(merged);
                }
                Opcode::BinaryRShift => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_bitwise(BitwiseOp::RShift));
                    self.push_meta(merged);
                }
                Opcode::BinaryMatMul => todo!("BinaryMatMul not implemented"),
                // Comparison Operations
                Opcode::CompareEq => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    self.compare_eq();
                    self.push_meta(merged);
                }
                Opcode::CompareNe => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    self.compare_ne();
                    self.push_meta(merged);
                }
                Opcode::CompareLt => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    self.compare_ord(Ordering::is_lt);
                    self.push_meta(merged);
                }
                Opcode::CompareLe => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    self.compare_ord(Ordering::is_le);
                    self.push_meta(merged);
                }
                Opcode::CompareGt => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    self.compare_ord(Ordering::is_gt);
                    self.push_meta(merged);
                }
                Opcode::CompareGe => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    self.compare_ord(Ordering::is_ge);
                    self.push_meta(merged);
                }
                Opcode::CompareIs => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    self.compare_is(false);
                    self.push_meta(merged);
                }
                Opcode::CompareIsNot => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    self.compare_is(true);
                    self.push_meta(merged);
                }
                Opcode::CompareIn => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.compare_in(false));
                    self.push_meta(merged);
                }
                Opcode::CompareNotIn => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.compare_in(true));
                    self.push_meta(merged);
                }
                Opcode::CompareModEq => {
                    let const_idx = fetch_u16!(cached_frame);
                    let k = cached_frame.code.constants().get(const_idx);
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.compare_mod_eq(k));
                    self.push_meta(merged);
                }
                // Unary Operations
                Opcode::UnaryNot => {
                    let meta = self.pop_meta();
                    let value = self.pop();
                    let result = !value.py_bool(self.heap, self.interns);
                    value.drop_with_heap(self.heap);
                    self.push(Value::Bool(result));
                    self.push_meta(meta);
                }
                Opcode::UnaryNeg => {
                    // Unary minus - negate numeric value
                    let meta = self.pop_meta();
                    let value = self.pop();
                    match value {
                        Value::Int(n) => {
                            // Use checked_neg to handle i64::MIN overflow
                            if let Some(negated) = n.checked_neg() {
                                self.push(Value::Int(negated));
                                self.push_meta(meta);
                            } else {
                                // i64::MIN negated overflows to LongInt
                                let li = -LongInt::from(n);
                                match li.into_value(self.heap) {
                                    Ok(v) => {
                                        self.push(v);
                                        self.push_meta(meta);
                                    }
                                    Err(e) => catch_sync!(self, cached_frame, RunError::from(e)),
                                }
                            }
                        }
                        Value::Float(f) => {
                            self.push(Value::Float(-f));
                            self.push_meta(meta);
                        }
                        Value::Bool(b) => {
                            self.push(Value::Int(if b { -1 } else { 0 }));
                            self.push_meta(meta);
                        }
                        Value::Ref(id) => {
                            if let HeapData::LongInt(li) = self.heap.get(id) {
                                let negated = -LongInt::new(li.inner().clone());
                                value.drop_with_heap(self.heap);
                                match negated.into_value(self.heap) {
                                    Ok(v) => {
                                        self.push(v);
                                        self.push_meta(meta);
                                    }
                                    Err(e) => catch_sync!(self, cached_frame, RunError::from(e)),
                                }
                            } else {
                                let value_type = value.py_type(self.heap);
                                value.drop_with_heap(self.heap);
                                catch_sync!(self, cached_frame, ExcType::unary_type_error("-", value_type));
                            }
                        }
                        _ => {
                            let value_type = value.py_type(self.heap);
                            value.drop_with_heap(self.heap);
                            catch_sync!(self, cached_frame, ExcType::unary_type_error("-", value_type));
                        }
                    }
                }
                Opcode::UnaryPos => {
                    // Unary plus - converts bools to int, no-op for other numbers
                    let meta = self.pop_meta();
                    let value = self.pop();
                    match value {
                        Value::Int(_) | Value::Float(_) => {
                            self.push(value);
                            self.push_meta(meta);
                        }
                        Value::Bool(b) => {
                            self.push(Value::Int(i64::from(b)));
                            self.push_meta(meta);
                        }
                        Value::Ref(id) => {
                            if matches!(self.heap.get(id), HeapData::LongInt(_)) {
                                // LongInt - return as-is (value already has correct refcount)
                                self.push(value);
                                self.push_meta(meta);
                            } else {
                                let value_type = value.py_type(self.heap);
                                value.drop_with_heap(self.heap);
                                catch_sync!(self, cached_frame, ExcType::unary_type_error("+", value_type));
                            }
                        }
                        _ => {
                            let value_type = value.py_type(self.heap);
                            value.drop_with_heap(self.heap);
                            catch_sync!(self, cached_frame, ExcType::unary_type_error("+", value_type));
                        }
                    }
                }
                Opcode::UnaryInvert => {
                    // Bitwise NOT
                    let meta = self.pop_meta();
                    let value = self.pop();
                    match value {
                        Value::Int(n) => {
                            self.push(Value::Int(!n));
                            self.push_meta(meta);
                        }
                        Value::Bool(b) => {
                            self.push(Value::Int(!i64::from(b)));
                            self.push_meta(meta);
                        }
                        Value::Ref(id) => {
                            if let HeapData::LongInt(li) = self.heap.get(id) {
                                // LongInt bitwise NOT: ~x = -(x + 1)
                                let inverted = -(li.inner() + 1i32);
                                value.drop_with_heap(self.heap);
                                match LongInt::new(inverted).into_value(self.heap) {
                                    Ok(v) => {
                                        self.push(v);
                                        self.push_meta(meta);
                                    }
                                    Err(e) => catch_sync!(self, cached_frame, RunError::from(e)),
                                }
                            } else {
                                let value_type = value.py_type(self.heap);
                                value.drop_with_heap(self.heap);
                                catch_sync!(self, cached_frame, ExcType::unary_type_error("~", value_type));
                            }
                        }
                        _ => {
                            let value_type = value.py_type(self.heap);
                            value.drop_with_heap(self.heap);
                            catch_sync!(self, cached_frame, ExcType::unary_type_error("~", value_type));
                        }
                    }
                }
                // In-place Operations - route through exception handling
                Opcode::InplaceAdd => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.inplace_add());
                    self.push_meta(merged);
                }
                // Other in-place ops use the same logic as binary ops for now
                Opcode::InplaceSub => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_sub());
                    self.push_meta(merged);
                }
                Opcode::InplaceMul => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_mult());
                    self.push_meta(merged);
                }
                Opcode::InplaceDiv => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_div());
                    self.push_meta(merged);
                }
                Opcode::InplaceFloorDiv => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_floordiv());
                    self.push_meta(merged);
                }
                Opcode::InplaceMod => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_mod());
                    self.push_meta(merged);
                }
                Opcode::InplacePow => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_pow());
                    self.push_meta(merged);
                }
                Opcode::InplaceAnd => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_bitwise(BitwiseOp::And));
                    self.push_meta(merged);
                }
                Opcode::InplaceOr => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_bitwise(BitwiseOp::Or));
                    self.push_meta(merged);
                }
                Opcode::InplaceXor => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_bitwise(BitwiseOp::Xor));
                    self.push_meta(merged);
                }
                Opcode::InplaceLShift => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_bitwise(BitwiseOp::LShift));
                    self.push_meta(merged);
                }
                Opcode::InplaceRShift => {
                    let rhs_meta = self.pop_meta();
                    let lhs_meta = self.pop_meta();
                    let merged = lhs_meta.merge(&rhs_meta);
                    try_catch_sync!(self, cached_frame, self.binary_bitwise(BitwiseOp::RShift));
                    self.push_meta(merged);
                }
                // Collection Building - route through exception handling
                Opcode::BuildList => {
                    let count = fetch_u16!(cached_frame) as usize;
                    let item_metas = self.pop_n_meta(count);
                    let merged = Metadata::merge_all(item_metas.iter());
                    try_catch_sync!(self, cached_frame, self.build_list(count));
                    self.push_meta(merged);
                }
                Opcode::BuildTuple => {
                    let count = fetch_u16!(cached_frame) as usize;
                    let item_metas = self.pop_n_meta(count);
                    let merged = Metadata::merge_all(item_metas.iter());
                    try_catch_sync!(self, cached_frame, self.build_tuple(count));
                    self.push_meta(merged);
                }
                Opcode::BuildDict => {
                    let count = fetch_u16!(cached_frame) as usize;
                    let item_metas = self.pop_n_meta(count * 2);
                    let merged = Metadata::merge_all(item_metas.iter());
                    try_catch_sync!(self, cached_frame, self.build_dict(count));
                    self.push_meta(merged);
                }
                Opcode::BuildSet => {
                    let count = fetch_u16!(cached_frame) as usize;
                    let item_metas = self.pop_n_meta(count);
                    let merged = Metadata::merge_all(item_metas.iter());
                    try_catch_sync!(self, cached_frame, self.build_set(count));
                    self.push_meta(merged);
                }
                Opcode::FormatValue => {
                    let flags = fetch_u8!(cached_frame);
                    let value_meta = self.pop_meta();
                    try_catch_sync!(self, cached_frame, self.format_value(flags));
                    self.push_meta(value_meta);
                }
                Opcode::BuildFString => {
                    let count = fetch_u16!(cached_frame) as usize;
                    let part_metas = self.pop_n_meta(count);
                    let merged = Metadata::merge_all(part_metas.iter());
                    try_catch_sync!(self, cached_frame, self.build_fstring(count));
                    self.push_meta(merged);
                }
                Opcode::BuildSlice => {
                    let item_metas = self.pop_n_meta(3);
                    let merged = Metadata::merge_all(item_metas.iter());
                    try_catch_sync!(self, cached_frame, self.build_slice());
                    self.push_meta(merged);
                }
                Opcode::ListExtend => {
                    // list_extend pops iterable, extends list in-place, pushes list back
                    // Pop iterable meta (consumed); list meta stays as it was
                    let _iter_meta = self.pop_meta();
                    // Also pop the list meta (list_extend pops and re-pushes the list)
                    let list_meta = self.pop_meta();
                    try_catch_sync!(self, cached_frame, self.list_extend());
                    self.push_meta(list_meta);
                }
                Opcode::ListToTuple => {
                    let list_meta = self.pop_meta();
                    try_catch_sync!(self, cached_frame, self.list_to_tuple());
                    self.push_meta(list_meta);
                }
                Opcode::DictMerge => {
                    let func_name_id = fetch_u16!(cached_frame);
                    // dict_merge pops mapping, pops dict, re-pushes dict
                    let _mapping_meta = self.pop_meta();
                    let dict_meta = self.pop_meta();
                    try_catch_sync!(self, cached_frame, self.dict_merge(func_name_id));
                    self.push_meta(dict_meta);
                }
                // Comprehension Building - append/add/set items during iteration
                Opcode::ListAppend => {
                    let depth = fetch_u8!(cached_frame) as usize;
                    let _item_meta = self.pop_meta();
                    try_catch_sync!(self, cached_frame, self.list_append(depth));
                }
                Opcode::SetAdd => {
                    let depth = fetch_u8!(cached_frame) as usize;
                    let _item_meta = self.pop_meta();
                    try_catch_sync!(self, cached_frame, self.set_add(depth));
                }
                Opcode::DictSetItem => {
                    let depth = fetch_u8!(cached_frame) as usize;
                    let _value_meta = self.pop_meta();
                    let _key_meta = self.pop_meta();
                    try_catch_sync!(self, cached_frame, self.dict_set_item(depth));
                }
                // Subscript & Attribute - route through exception handling
                Opcode::BinarySubscr => {
                    let index_meta = self.pop_meta();
                    let index = self.pop();
                    let obj_meta = self.pop_meta();
                    let obj = self.pop();
                    let merged_meta = obj_meta.merge(&index_meta);
                    let result = obj.py_getitem(&index, self.heap, self.interns);
                    obj.drop_with_heap(self.heap);
                    index.drop_with_heap(self.heap);
                    match result {
                        Ok(v) => {
                            self.push(v);
                            self.push_meta(merged_meta);
                        }
                        Err(e) => catch_sync!(self, cached_frame, e),
                    }
                }
                Opcode::StoreSubscr => {
                    // Stack order: value, obj, index (TOS)
                    let _index_meta = self.pop_meta();
                    let index = self.pop();
                    let _obj_meta = self.pop_meta();
                    let mut obj = self.pop();
                    let _value_meta = self.pop_meta();
                    let value = self.pop();
                    let result = obj.py_setitem(index, value, self.heap, self.interns);
                    obj.drop_with_heap(self.heap);
                    if let Err(e) = result {
                        catch_sync!(self, cached_frame, e);
                    }
                }
                Opcode::DeleteSubscr => {
                    // TODO: Implement py_delitem on Value
                    let _index_meta = self.pop_meta();
                    let index = self.pop();
                    let _obj_meta = self.pop_meta();
                    let obj = self.pop();
                    obj.drop_with_heap(self.heap);
                    index.drop_with_heap(self.heap);
                    todo!("DeleteSubscr: py_delitem not yet implemented")
                }
                Opcode::LoadAttr => {
                    let name_idx = fetch_u16!(cached_frame);
                    let name_id = StringId::from_index(name_idx);
                    // Object meta consumed; handle_call_result! syncs meta stack via truncate
                    handle_call_result!(self, cached_frame, self.load_attr(name_id));
                }
                Opcode::LoadAttrImport => {
                    let name_idx = fetch_u16!(cached_frame);
                    let name_id = StringId::from_index(name_idx);
                    // Object meta consumed; handle_call_result! syncs meta stack via truncate
                    handle_call_result!(self, cached_frame, self.load_attr_import(name_id));
                }
                Opcode::StoreAttr => {
                    let name_idx = fetch_u16!(cached_frame);
                    let name_id = StringId::from_index(name_idx);
                    // store_attr pops value and obj internally
                    try_catch_sync!(self, cached_frame, self.store_attr(name_id));
                    self.stack_meta.truncate(self.stack.len());
                }
                Opcode::DeleteAttr => {
                    todo!("DeleteAttr not implemented")
                }
                // Control Flow - use cached_frame.ip directly for jumps
                Opcode::Jump => {
                    let offset = fetch_i16!(cached_frame);
                    jump_relative!(cached_frame.ip, offset);
                }
                Opcode::JumpIfTrue => {
                    let offset = fetch_i16!(cached_frame);
                    let cond = self.pop();
                    let cond_meta = self.pop_meta();
                    // Branch checker validates that untrusted metadata cannot influence control flow
                    if let Some(ref checker) = self.branch_checker
                        && let Err(exc) = checker.check(&cond_meta)
                    {
                        cond.drop_with_heap(self.heap);
                        let run_error = crate::exception_private::RunError::from(exc);
                        if let Some(result) = self.handle_exception(run_error) {
                            return Err(result);
                        }
                        reload_cache!(self, cached_frame);
                        continue;
                    }
                    if cond.py_bool(self.heap, self.interns) {
                        jump_relative!(cached_frame.ip, offset);
                    }
                    cond.drop_with_heap(self.heap);
                }
                Opcode::JumpIfFalse => {
                    let offset = fetch_i16!(cached_frame);
                    let cond = self.pop();
                    let cond_meta = self.pop_meta();
                    // Branch checker validates that untrusted metadata cannot influence control flow
                    if let Some(ref checker) = self.branch_checker
                        && let Err(exc) = checker.check(&cond_meta)
                    {
                        cond.drop_with_heap(self.heap);
                        let run_error = crate::exception_private::RunError::from(exc);
                        if let Some(result) = self.handle_exception(run_error) {
                            return Err(result);
                        }
                        reload_cache!(self, cached_frame);
                        continue;
                    }
                    if !cond.py_bool(self.heap, self.interns) {
                        jump_relative!(cached_frame.ip, offset);
                    }
                    cond.drop_with_heap(self.heap);
                }
                Opcode::JumpIfTrueOrPop => {
                    let offset = fetch_i16!(cached_frame);
                    let cond_meta = self.peek_meta().clone();
                    // Branch checker validates metadata
                    if let Some(ref checker) = self.branch_checker
                        && let Err(exc) = checker.check(&cond_meta)
                    {
                        let value = self.pop();
                        let _meta = self.pop_meta();
                        value.drop_with_heap(self.heap);
                        let run_error = crate::exception_private::RunError::from(exc);
                        if let Some(result) = self.handle_exception(run_error) {
                            return Err(result);
                        }
                        reload_cache!(self, cached_frame);
                        continue;
                    }
                    if self.peek().py_bool(self.heap, self.interns) {
                        jump_relative!(cached_frame.ip, offset);
                    } else {
                        let value = self.pop();
                        let _meta = self.pop_meta();
                        value.drop_with_heap(self.heap);
                    }
                }
                Opcode::JumpIfFalseOrPop => {
                    let offset = fetch_i16!(cached_frame);
                    let cond_meta = self.peek_meta().clone();
                    // Branch checker validates metadata
                    if let Some(ref checker) = self.branch_checker
                        && let Err(exc) = checker.check(&cond_meta)
                    {
                        let value = self.pop();
                        let _meta = self.pop_meta();
                        value.drop_with_heap(self.heap);
                        let run_error = crate::exception_private::RunError::from(exc);
                        if let Some(result) = self.handle_exception(run_error) {
                            return Err(result);
                        }
                        reload_cache!(self, cached_frame);
                        continue;
                    }
                    if self.peek().py_bool(self.heap, self.interns) {
                        let value = self.pop();
                        let _meta = self.pop_meta();
                        value.drop_with_heap(self.heap);
                    } else {
                        jump_relative!(cached_frame.ip, offset);
                    }
                }
                // Iteration - route through exception handling
                Opcode::GetIter => {
                    let value = self.pop();
                    let value_meta = self.pop_meta();
                    // Create a MontyIter from the value and store on heap
                    match MontyIter::new(value, self.heap, self.interns) {
                        Ok(iter) => match self.heap.allocate(HeapData::Iter(iter)) {
                            Ok(heap_id) => {
                                self.push(Value::Ref(heap_id));
                                self.push_meta(value_meta);
                            }
                            Err(e) => catch_sync!(self, cached_frame, e.into()),
                        },
                        Err(e) => catch_sync!(self, cached_frame, e),
                    }
                }
                Opcode::ForIter => {
                    let offset = fetch_i16!(cached_frame);
                    // Peek at the iterator on TOS and extract heap_id
                    let Value::Ref(heap_id) = *self.peek() else {
                        return Err(RunError::internal("ForIter: expected iterator ref on stack"));
                    };

                    // Clone iterator's metadata for the yielded value
                    let iter_meta = self.peek_meta().clone();

                    // Use advance_iterator which avoids std::mem::replace overhead
                    // by using a two-phase approach: read state, get value, update index
                    match advance_on_heap(self.heap, heap_id, self.interns) {
                        Ok(Some(value)) => {
                            self.push(value);
                            self.push_meta(iter_meta);
                        }
                        Ok(None) => {
                            // Iterator exhausted - pop it and jump to end
                            let iter = self.pop();
                            let _iter_meta = self.pop_meta();
                            iter.drop_with_heap(self.heap);
                            jump_relative!(cached_frame.ip, offset);
                        }
                        Err(e) => {
                            // Error during iteration (e.g., dict size changed)
                            let iter = self.pop();
                            let _iter_meta = self.pop_meta();
                            iter.drop_with_heap(self.heap);
                            catch_sync!(self, cached_frame, e);
                        }
                    }
                }
                // Function Calls - sync IP before call, reload cache after frame changes
                Opcode::CallFunction => {
                    let arg_count = fetch_u8!(cached_frame) as usize;

                    // Sync IP before call (call_function may access frame for traceback)
                    self.current_frame_mut().ip = cached_frame.ip;

                    handle_call_result!(self, cached_frame, self.exec_call_function(arg_count));
                }
                Opcode::CallBuiltinFunction => {
                    // Fetch operands: builtin_id (u8) + arg_count (u8)
                    let builtin_id = fetch_u8!(cached_frame);
                    let arg_count = fetch_u8!(cached_frame) as usize;

                    match self.exec_call_builtin_function(builtin_id, arg_count) {
                        Ok(result) => {
                            self.stack_meta.truncate(self.stack.len());
                            self.push(result);
                            self.push_meta(Metadata::default());
                        }
                        // IP sync deferred to error path (no frame push possible)
                        Err(err) => {
                            self.stack_meta.truncate(self.stack.len());
                            catch_sync!(self, cached_frame, err);
                        }
                    }
                }
                Opcode::CallBuiltinType => {
                    // Fetch operands: type_id (u8) + arg_count (u8)
                    let type_id = fetch_u8!(cached_frame);
                    let arg_count = fetch_u8!(cached_frame) as usize;

                    match self.exec_call_builtin_type(type_id, arg_count) {
                        Ok(result) => {
                            self.stack_meta.truncate(self.stack.len());
                            self.push(result);
                            self.push_meta(Metadata::default());
                        }
                        // IP sync deferred to error path (no frame push possible)
                        Err(err) => {
                            self.stack_meta.truncate(self.stack.len());
                            catch_sync!(self, cached_frame, err);
                        }
                    }
                }
                Opcode::CallFunctionKw => {
                    // Fetch operands: pos_count, kw_count, then kw_count name indices
                    let pos_count = fetch_u8!(cached_frame) as usize;
                    let kw_count = fetch_u8!(cached_frame) as usize;

                    // Read keyword name StringIds
                    let mut kwname_ids = Vec::with_capacity(kw_count);
                    for _ in 0..kw_count {
                        kwname_ids.push(StringId::from_index(fetch_u16!(cached_frame)));
                    }

                    // Sync IP before call (call_function may access frame for traceback)
                    self.current_frame_mut().ip = cached_frame.ip;

                    handle_call_result!(self, cached_frame, self.exec_call_function_kw(pos_count, kwname_ids));
                }
                Opcode::CallAttr => {
                    // CallAttr: u16 name_id, u8 arg_count
                    // Stack: [obj, arg1, arg2, ..., argN] -> [result]
                    let name_idx = fetch_u16!(cached_frame);
                    let arg_count = fetch_u8!(cached_frame) as usize;
                    let name_id = StringId::from_index(name_idx);

                    // Sync IP before call (may yield to host for OS/external calls)
                    self.current_frame_mut().ip = cached_frame.ip;

                    handle_call_result!(self, cached_frame, self.exec_call_attr(name_id, arg_count));
                }
                Opcode::CallAttrKw => {
                    // CallAttrKw: u16 name_id, u8 pos_count, u8 kw_count, then kw_count u16 name indices
                    // Stack: [obj, pos_args..., kw_values...] -> [result]
                    let name_idx = fetch_u16!(cached_frame);
                    let pos_count = fetch_u8!(cached_frame) as usize;
                    let kw_count = fetch_u8!(cached_frame) as usize;
                    let name_id = StringId::from_index(name_idx);

                    // Read keyword name StringIds
                    let mut kwname_ids = Vec::with_capacity(kw_count);
                    for _ in 0..kw_count {
                        kwname_ids.push(StringId::from_index(fetch_u16!(cached_frame)));
                    }

                    // Sync IP before call (may yield to host for OS/external calls)
                    self.current_frame_mut().ip = cached_frame.ip;

                    handle_call_result!(
                        self,
                        cached_frame,
                        self.exec_call_attr_kw(name_id, pos_count, kwname_ids)
                    );
                }
                Opcode::CallFunctionExtended => {
                    let flags = fetch_u8!(cached_frame);
                    let has_kwargs = (flags & 0x01) != 0;

                    // Sync IP before call
                    self.current_frame_mut().ip = cached_frame.ip;

                    handle_call_result!(self, cached_frame, self.exec_call_function_extended(has_kwargs));
                }
                Opcode::CallAttrExtended => {
                    let name_idx = fetch_u16!(cached_frame);
                    let flags = fetch_u8!(cached_frame);
                    let name_id = StringId::from_index(name_idx);
                    let has_kwargs = (flags & 0x01) != 0;

                    // Sync IP before call (may yield to host for OS/external calls)
                    self.current_frame_mut().ip = cached_frame.ip;

                    handle_call_result!(self, cached_frame, self.exec_call_attr_extended(name_id, has_kwargs));
                }
                // Function Definition
                Opcode::MakeFunction => {
                    let func_idx = fetch_u16!(cached_frame);
                    let defaults_count = fetch_u8!(cached_frame) as usize;
                    let func_id = FunctionId::from_index(func_idx);

                    if defaults_count == 0 {
                        // No defaults - use inline Value::Function (no heap allocation)
                        self.push(Value::DefFunction(func_id));
                        self.push_meta(Metadata::default());
                    } else {
                        // Pop metadata for default values
                        let _defaults_meta = self.pop_n_meta(defaults_count);
                        // Pop default values from stack (drain maintains order: first pushed = first in vec)
                        let defaults = self.pop_n(defaults_count);

                        // Create FunctionDefaults on heap and push reference
                        let heap_id = self.heap.allocate(HeapData::FunctionDefaults(func_id, defaults))?;
                        self.push(Value::Ref(heap_id));
                        self.push_meta(Metadata::default());
                    }
                }
                Opcode::MakeClosure => {
                    let func_idx = fetch_u16!(cached_frame);
                    let defaults_count = fetch_u8!(cached_frame) as usize;
                    let cell_count = fetch_u8!(cached_frame) as usize;
                    let func_id = FunctionId::from_index(func_idx);

                    // Pop cell metas
                    let _cell_metas = self.pop_n_meta(cell_count);
                    // Pop cells from stack (pushed after defaults, so on top)
                    // Cells are Value::Ref pointing to HeapData::Cell
                    // We use individual pops which reverses order, so we need to reverse back
                    let mut cells = Vec::with_capacity(cell_count);
                    for _ in 0..cell_count {
                        let cell_val = self.pop();
                        match &cell_val {
                            Value::Ref(heap_id) => {
                                // Keep the reference - the Closure will own the HeapId
                                cells.push(*heap_id);
                            }
                            _ => {
                                return Err(RunError::internal("MakeClosure: expected cell reference on stack"));
                            }
                        }
                    }
                    // Reverse to get original order (individual pops reverse the order)
                    cells.reverse();

                    // Pop default metas
                    let _defaults_meta = self.pop_n_meta(defaults_count);
                    // Pop default values from stack (drain maintains order: first pushed = first in vec)
                    let defaults = self.pop_n(defaults_count);

                    // Create Closure on heap and push reference
                    let heap_id = self.heap.allocate(HeapData::Closure(func_id, cells, defaults))?;
                    self.push(Value::Ref(heap_id));
                    self.push_meta(Metadata::default());
                }
                // Exception Handling
                Opcode::Raise => {
                    let exc = self.pop();
                    let _exc_meta = self.pop_meta();
                    let error = self.make_exception(exc, true); // is_raise=true, hide caret
                    catch_sync!(self, cached_frame, error);
                }
                Opcode::RaiseFrom => {
                    todo!("RaiseFrom")
                }
                Opcode::Reraise => {
                    // Pop the current exception from the stack to re-raise it
                    // If caught, handle_exception will push it back
                    let error = if let Some(exc) = self.exception_stack.pop() {
                        self.make_exception(exc, true) // is_raise=true for reraise
                    } else {
                        // No active exception - create a RuntimeError
                        SimpleException::new_msg(ExcType::RuntimeError, "No active exception to reraise").into()
                    };
                    catch_sync!(self, cached_frame, error);
                }
                Opcode::ClearException => {
                    // Pop the current exception from the stack
                    // This restores the previous exception context (if any)
                    if let Some(exc) = self.exception_stack.pop() {
                        exc.drop_with_heap(self.heap);
                    }
                }
                Opcode::CheckExcMatch => {
                    // Stack: [exception, exc_type] -> [exception, bool]
                    let _exc_type_meta = self.pop_meta();
                    let exc_type = self.pop();
                    let exception = self.peek();
                    let result = self.check_exc_match(exception, &exc_type);
                    exc_type.drop_with_heap(self.heap);
                    let result = result?;
                    self.push(Value::Bool(result));
                    self.push_meta(Metadata::default());
                }
                // Return - reload cache after popping frame
                Opcode::ReturnValue => {
                    let value = self.pop();
                    let return_meta = self.pop_meta();
                    if self.frames.len() == 1 {
                        // Last frame - check if this is main task or spawned task
                        let is_main_task = self.is_main_task();

                        if is_main_task {
                            // Module-level return - we're done
                            return Ok(FrameExit::Return(value, return_meta));
                        }

                        // Spawned task completed - handle task completion
                        let result = self.handle_task_completion(value);
                        match result {
                            Ok(AwaitResult::ValueReady(v)) => {
                                self.push(v);
                                self.push_meta(return_meta);
                            }
                            Ok(AwaitResult::FramePushed) => {
                                // Switched to another task - reload cache
                                reload_cache!(self, cached_frame);
                            }
                            Ok(AwaitResult::Yield(pending)) => {
                                // All tasks blocked - return to host
                                return Ok(FrameExit::ResolveFutures(pending));
                            }
                            Err(e) => {
                                catch_sync!(self, cached_frame, e);
                            }
                        }
                        continue;
                    }
                    // Pop current frame and push return value
                    self.pop_frame();
                    self.push(value);
                    self.push_meta(return_meta);
                    // Reload cache from parent frame
                    reload_cache!(self, cached_frame);
                }
                // Async/Await
                Opcode::Await => {
                    // The awaitable is consumed from stack by exec_get_awaitable
                    let _awaitable_meta = self.pop_meta();
                    // Sync IP before exec (may push new frame for coroutine)
                    self.current_frame_mut().ip = cached_frame.ip;
                    let result = self.exec_get_awaitable();
                    self.stack_meta.truncate(self.stack.len());
                    match result {
                        Ok(AwaitResult::ValueReady(value)) => {
                            self.push(value);
                            self.push_meta(Metadata::default());
                        }
                        Ok(AwaitResult::FramePushed) => {
                            // Reload cache after pushing a new frame
                            reload_cache!(self, cached_frame);
                        }
                        Ok(AwaitResult::Yield(pending_calls)) => {
                            // All tasks are blocked - return control to host
                            return Ok(FrameExit::ResolveFutures(pending_calls));
                        }
                        Err(e) => {
                            catch_sync!(self, cached_frame, e);
                        }
                    }
                }
                // Unpacking - route through exception handling
                Opcode::UnpackSequence => {
                    let count = fetch_u8!(cached_frame) as usize;
                    let seq_meta = self.pop_meta();
                    try_catch_sync!(self, cached_frame, self.unpack_sequence(count));
                    // Each unpacked element inherits the sequence's metadata
                    for _ in 0..count {
                        self.push_meta(seq_meta.clone());
                    }
                }
                Opcode::UnpackEx => {
                    let before = fetch_u8!(cached_frame) as usize;
                    let after = fetch_u8!(cached_frame) as usize;
                    let seq_meta = self.pop_meta();
                    try_catch_sync!(self, cached_frame, self.unpack_ex(before, after));
                    // Each unpacked element (before + starred list + after) inherits metadata
                    let total = before + 1 + after;
                    for _ in 0..total {
                        self.push_meta(seq_meta.clone());
                    }
                }
                // Special
                Opcode::Nop => {
                    // No operation
                }
                // Module Operations
                Opcode::LoadModule => {
                    let module_id = fetch_u8!(cached_frame);
                    try_catch_sync!(self, cached_frame, self.load_module(module_id));
                    self.push_meta(Metadata::default());
                }
                Opcode::RaiseImportError => {
                    // Fetch the module name from the constant pool and raise ModuleNotFoundError
                    let const_idx = fetch_u16!(cached_frame);
                    let module_name = cached_frame.code.constants().get(const_idx);
                    // The constant should be an InternString from compile_import/compile_import_from
                    let name_str = match module_name {
                        Value::InternString(id) => self.interns.get_str(*id),
                        _ => "<unknown>",
                    };
                    let error = ExcType::module_not_found_error(name_str);
                    catch_sync!(self, cached_frame, error);
                }
            }
        }
    }

    /// Loads a built-in module and pushes it onto the stack.
    fn load_module(&mut self, module_id: u8) -> RunResult<()> {
        let module = BuiltinModule::from_repr(module_id).expect("unknown module id");

        // Create the module on the heap using pre-interned strings
        let heap_id = module.create(self.heap, self.interns)?;
        self.push(Value::Ref(heap_id));
        Ok(())
    }

    /// Resumes execution after an external call completes.
    ///
    /// Pushes the return value and its metadata onto the stack and continues execution.
    pub fn resume(&mut self, obj: MontyObject, return_meta: Metadata) -> Result<FrameExit, RunError> {
        let value = obj
            .to_value(self.heap, self.interns)
            .map_err(|e| SimpleException::new(ExcType::RuntimeError, Some(format!("invalid return type: {e}"))))?;
        self.push(value);
        self.push_meta(return_meta);
        self.run()
    }

    /// Resumes execution after an external call raised an exception.
    ///
    /// Uses the exception handling mechanism to try to catch the exception.
    /// If caught, continues execution at the handler. If not, propagates the error.
    pub fn resume_with_exception(&mut self, error: RunError) -> Result<FrameExit, RunError> {
        // Use the normal exception handling mechanism
        // handle_exception returns None if caught, Some(error) if not caught
        if let Some(uncaught_error) = self.handle_exception(error) {
            return Err(uncaught_error);
        }
        // Exception was caught, continue execution
        self.run()
    }

    // ========================================================================
    // Stack Operations
    // ========================================================================

    /// Pushes a value onto the operand stack.
    #[inline]
    pub(crate) fn push(&mut self, value: Value) {
        self.stack.push(value);
    }

    /// Pops a value from the operand stack.
    #[inline]
    pub(super) fn pop(&mut self) -> Value {
        self.stack.pop().expect("stack underflow")
    }

    /// Peeks at the top of the operand stack without removing it.
    #[inline]
    pub(super) fn peek(&self) -> &Value {
        self.stack.last().expect("stack underflow")
    }

    /// Pops n values from the stack in reverse order (first popped is last in vec).
    pub(super) fn pop_n(&mut self, n: usize) -> Vec<Value> {
        let start = self.stack.len() - n;
        self.stack.drain(start..).collect()
    }

    // ========================================================================
    // Stack Metadata Operations
    // ========================================================================

    /// Pushes metadata for the corresponding stack value.
    #[inline]
    pub(crate) fn push_meta(&mut self, meta: Metadata) {
        self.stack_meta.push(meta);
    }

    /// Pops metadata from the metadata stack.
    #[inline]
    pub(super) fn pop_meta(&mut self) -> Metadata {
        self.stack_meta.pop().expect("metadata stack underflow")
    }

    /// Peeks at the top metadata without removing it.
    #[inline]
    pub(super) fn peek_meta(&self) -> &Metadata {
        self.stack_meta.last().expect("metadata stack underflow")
    }

    /// Pops n metadata entries from the stack (maintains order like pop_n).
    pub(super) fn pop_n_meta(&mut self, n: usize) -> Vec<Metadata> {
        let start = self.stack_meta.len() - n;
        self.stack_meta.drain(start..).collect()
    }

    /// Extracts positional argument metadata from the stack_meta surplus.
    ///
    /// After a call opcode pops values from the value stack (via `pop_n_args` + `pop`)
    /// but before `stack_meta` is truncated, a "surplus" of metadata entries remains
    /// in `stack_meta` that correspond to the popped values in stack order (bottom to top):
    ///
    /// ```text
    /// [callable_or_obj_meta, arg0_meta, arg1_meta, ..., arg_{n-1}_meta, [kw_metas...]]
    /// ```
    ///
    /// This method:
    /// 1. Skips the first surplus entry (callable/receiver object metadata)
    /// 2. Takes up to `pos_count` entries for positional argument metadata
    /// 3. For extended calls (tuple unpacking) where fewer surplus entries exist
    ///    than `pos_count`, merges available entries and broadcasts to all positions
    fn extract_args_meta_from_surplus(&self, pos_count: usize) -> Vec<Metadata> {
        let surplus_start = self.stack.len();
        let surplus_count = self.stack_meta.len() - surplus_start;

        if surplus_count <= 1 || pos_count == 0 {
            // No args metadata: only callable/obj meta in surplus, or no args
            return Vec::new();
        }

        let available_after_skip = surplus_count - 1; // skip callable/obj meta

        if available_after_skip >= pos_count {
            // Simple call path: 1:1 mapping between surplus entries and positional args
            self.stack_meta[surplus_start + 1..surplus_start + 1 + pos_count].to_vec()
        } else {
            // Extended call path: fewer surplus entries than args (tuple was unpacked)
            // Merge all non-callable surplus entries and broadcast to all positions
            let merged = Metadata::merge_all(
                self.stack_meta[surplus_start + 1..surplus_start + surplus_count].iter(),
            );
            vec![merged; pos_count]
        }
    }

    /// Sets the branch checker for policy enforcement at conditional jumps.
    /// Used by the interpreter layer (Phase 5) to inject policy enforcement.
    pub fn set_branch_checker(&mut self, checker: Box<dyn BranchChecker>) {
        self.branch_checker = Some(checker);
    }

    // ========================================================================
    // Frame Operations
    // ========================================================================

    /// Returns a reference to the current (topmost) call frame.
    #[inline]
    pub(super) fn current_frame(&self) -> &CallFrame<'a> {
        self.frames.last().expect("no active frame")
    }

    /// Creates a new cached frame from the current frame.
    #[inline]
    pub(super) fn new_cached_frame(&self) -> CachedFrame<'a> {
        self.current_frame().into()
    }

    /// Returns a mutable reference to the current call frame.
    #[inline]
    pub(super) fn current_frame_mut(&mut self) -> &mut CallFrame<'a> {
        self.frames.last_mut().expect("no active frame")
    }

    /// Pops the current frame from the call stack.
    ///
    /// Cleans up the frame's stack region and namespace (except for global namespace).
    pub(super) fn pop_frame(&mut self) {
        let frame = self.frames.pop().expect("no frame to pop");
        // Clean up frame's stack region
        while self.stack.len() > frame.stack_base {
            let value = self.stack.pop().unwrap();
            value.drop_with_heap(self.heap);
        }
        // Trim metadata stack to match value stack
        self.stack_meta.truncate(frame.stack_base);
        // Clean up the namespace (but not the global namespace)
        if frame.namespace_idx != GLOBAL_NS_IDX {
            self.namespaces.drop_with_heap(frame.namespace_idx, self.heap);
        }
    }

    /// Cleans up all frames for the current task before switching tasks.
    ///
    /// Used when a task completes or fails and we need to switch to another task.
    /// Properly cleans up each frame's namespace and cell references.
    pub(super) fn cleanup_current_frames(&mut self) {
        for frame in self.frames.drain(..) {
            // Clean up cell references
            for cell_id in frame.cells {
                self.heap.dec_ref(cell_id);
            }
            // Clean up the namespace (but not the global namespace)
            if frame.namespace_idx != GLOBAL_NS_IDX {
                self.namespaces.drop_with_heap(frame.namespace_idx, self.heap);
            }
        }
    }

    /// Runs garbage collection with proper GC roots.
    ///
    /// GC roots include values in namespaces, the operand stack, and exception stack.
    fn run_gc(&mut self) {
        // Collect roots from all reachable values
        let stack_roots = self.stack.iter().filter_map(Value::ref_id);
        let exc_roots = self.exception_stack.iter().filter_map(Value::ref_id);
        let ns_roots = self.namespaces.iter_heap_ids();

        // Collect all roots into a vec to avoid lifetime issues
        let roots: Vec<HeapId> = stack_roots.chain(exc_roots).chain(ns_roots).collect();

        self.heap.collect_garbage(roots);
    }

    /// Returns the current source position for traceback generation.
    ///
    /// Uses `instruction_ip` which is set at the start of each instruction in the run loop,
    /// ensuring accurate position tracking even when using cached IP for bytecode fetching.
    pub(super) fn current_position(&self) -> CodeRange {
        let frame = self.current_frame();
        // Use instruction_ip which points to the start of the current instruction
        // (set at the beginning of each loop iteration in run())
        frame
            .code
            .location_for_offset(self.instruction_ip)
            .map(crate::bytecode::code::LocationEntry::range)
            .unwrap_or_default()
    }

    // ========================================================================
    // Variable Operations
    // ========================================================================

    /// Loads a local variable and pushes it onto the stack.
    ///
    /// Returns `UnboundLocalError` if this is a true local (assigned somewhere in the function)
    /// or `NameError` if the name doesn't exist in any scope.
    fn load_local(&mut self, cached_frame: &CachedFrame<'a>, slot: u16) -> RunResult<()> {
        let namespace = self.namespaces.get(cached_frame.namespace_idx);
        // Copy without incrementing refcount first (avoids borrow conflict)
        let value = namespace.get(NamespaceId::new(slot as usize)).copy_for_extend();

        // Check for undefined value - raise appropriate error based on whether
        // this is a true local (assigned somewhere) or an undefined reference
        if matches!(value, Value::Undefined) {
            let name = cached_frame.code.local_name(slot);
            let err = if cached_frame.code.is_assigned_local(slot) {
                // True local accessed before assignment
                self.unbound_local_error(slot, name)
            } else {
                // Name doesn't exist in any scope
                self.name_error_for_local(slot, name)
            };
            return Err(err);
        }

        // Now we can safely increment refcount and push
        if let Value::Ref(id) = &value {
            self.heap.inc_ref(*id);
        }
        self.push(value);
        // Push the variable's metadata from the namespace
        let meta = self.namespaces.get(cached_frame.namespace_idx).get_meta(NamespaceId::new(slot as usize)).clone();
        self.push_meta(meta);
        Ok(())
    }

    /// Creates an UnboundLocalError for a local variable accessed before assignment.
    fn unbound_local_error(&self, slot: u16, name: Option<StringId>) -> RunError {
        let name_str = match name {
            Some(id) => self.interns.get_str(id).to_string(),
            None => format!("<local {slot}>"),
        };
        ExcType::unbound_local_error(&name_str).into()
    }

    /// Creates a NameError for an undefined global variable.
    fn name_error(&self, slot: u16, name: Option<StringId>) -> RunError {
        let name_str = match name {
            Some(id) => self.interns.get_str(id).to_string(),
            None => format!("<global {slot}>"),
        };
        ExcType::name_error(&name_str).into()
    }

    /// Creates a NameError for an undefined local variable.
    fn name_error_for_local(&self, slot: u16, name: Option<StringId>) -> RunError {
        let name_str = match name {
            Some(id) => self.interns.get_str(id).to_string(),
            None => format!("<local {slot}>"),
        };
        ExcType::name_error(&name_str).into()
    }

    /// Pops the top of stack and stores it in a local variable.
    fn store_local(&mut self, cached_frame: &CachedFrame<'a>, slot: u16) {
        let value = self.pop();
        let meta = self.pop_meta();
        let namespace = self.namespaces.get_mut(cached_frame.namespace_idx);
        let ns_slot = NamespaceId::new(slot as usize);
        let old_value = std::mem::replace(namespace.get_mut(ns_slot), value);
        namespace.set_meta(ns_slot, meta);
        old_value.drop_with_heap(self.heap);
    }

    /// Deletes a local variable (sets it to Undefined).
    fn delete_local(&mut self, cached_frame: &CachedFrame<'a>, slot: u16) {
        let namespace = self.namespaces.get_mut(cached_frame.namespace_idx);
        let ns_slot = NamespaceId::new(slot as usize);
        let old_value = std::mem::replace(namespace.get_mut(ns_slot), Value::Undefined);
        namespace.set_meta(ns_slot, Metadata::default());
        old_value.drop_with_heap(self.heap);
    }

    /// Loads a global variable and pushes it onto the stack.
    ///
    /// Returns a NameError if the variable is undefined.
    fn load_global(&mut self, slot: u16) -> RunResult<()> {
        let namespace = self.namespaces.get(GLOBAL_NS_IDX);
        // Copy without incrementing refcount first (avoids borrow conflict)
        let value = namespace
            .get(NamespaceId::new(slot as usize))
            .clone_with_heap(self.heap);

        // Check for undefined value - raise NameError if so
        if matches!(value, Value::Undefined) {
            // For globals, we'd need a global_names table too, but for now use a placeholder
            let name = self.current_frame().code.local_name(slot);
            Err(self.name_error(slot, name))
        } else {
            self.push(value);
            let meta = self.namespaces.get(GLOBAL_NS_IDX).get_meta(NamespaceId::new(slot as usize)).clone();
            self.push_meta(meta);
            Ok(())
        }
    }

    /// Pops the top of stack and stores it in a global variable.
    fn store_global(&mut self, slot: u16) {
        let value = self.pop();
        let meta = self.pop_meta();
        let namespace = self.namespaces.get_mut(GLOBAL_NS_IDX);
        let ns_slot = NamespaceId::new(slot as usize);
        let old_value = std::mem::replace(namespace.get_mut(ns_slot), value);
        namespace.set_meta(ns_slot, meta);
        old_value.drop_with_heap(self.heap);
    }

    /// Loads from a closure cell and pushes onto the stack.
    ///
    /// Returns a NameError if the cell value is undefined (free variable not bound).
    fn load_cell(&mut self, slot: u16) -> RunResult<()> {
        let cell_id = self.current_frame().cells[slot as usize];
        // get_cell_value already clones with proper refcount via clone_with_heap
        let value = self.heap.get_cell_value(cell_id);

        // Check for undefined value - raise NameError for unbound free variable
        if matches!(value, Value::Undefined) {
            let name = self.current_frame().code.local_name(slot);
            return Err(self.free_var_error(name));
        }

        self.push(value);
        // Closures are not in the PLLM subset; use default metadata
        self.push_meta(Metadata::default());
        Ok(())
    }

    /// Creates a NameError for an unbound free variable.
    fn free_var_error(&self, name: Option<StringId>) -> RunError {
        let name_str = match name {
            Some(id) => self.interns.get_str(id).to_string(),
            None => "<free var>".to_string(),
        };
        ExcType::name_error_free_variable(&name_str).into()
    }

    /// Pops the top of stack and stores it in a closure cell.
    fn store_cell(&mut self, slot: u16) {
        let value = self.pop();
        let _meta = self.pop_meta();
        let cell_id = self.current_frame().cells[slot as usize];
        self.heap.set_cell_value(cell_id, value);
    }
}

// `heap` is not a public field on VM, so this implementation needs to go here rather than in `heap.rs`
impl<T: ResourceTracker, P: PrintWriter> ContainsHeap<T> for VM<'_, T, P> {
    fn heap_mut(&mut self) -> &mut Heap<T> {
        self.heap
    }
}
