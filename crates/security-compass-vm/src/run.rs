//! Public interface for running Monty code.
use std::sync::atomic::{AtomicUsize, Ordering};

use security_compass_meta::Metadata;

use crate::{
    ExcType, MontyException,
    asyncio::CallId,
    bytecode::{Code, Compiler, FrameExit, VM, VMSnapshot},
    exception_private::RunResult,
    heap::Heap,
    intern::{ExtFunctionId, Interns},
    io::{PrintWriter, StdPrint},
    namespace::Namespaces,
    object::MontyObject,
    os::OsFunction,
    parse::parse,
    prepare::prepare,
    resource::{NoLimitTracker, ResourceTracker},
    value::Value,
};

/// Primary interface for running Monty code.
///
/// `MontyRun` supports two execution modes:
/// - **Simple execution**: Use `run()` or `run_no_limits()` to run code to completion
/// - **Iterative execution**: Use `start()` to start execution which will pause at external function calls and
///   can be resumed later
///
/// # Example
/// ```
/// use security_compass_vm::{MontyRun, MontyObject};
///
/// let runner = MontyRun::new("x + 1".to_owned(), "test.py", vec!["x".to_owned()], vec![]).unwrap();
/// let result = runner.run_no_limits(vec![MontyObject::Int(41)]).unwrap();
/// assert_eq!(result, MontyObject::Int(42));
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MontyRun {
    /// The underlying executor containing parsed AST and interns.
    executor: Executor,
}

impl MontyRun {
    /// Creates a new run snapshot by parsing the given code.
    ///
    /// This only parses and prepares the code - no heap or namespaces are created yet.
    /// Call `run_snapshot()` with inputs to start execution.
    ///
    /// # Arguments
    /// * `code` - The Python code to execute
    /// * `script_name` - The script name for error messages
    /// * `input_names` - Names of input variables
    ///
    /// # Errors
    /// Returns `MontyException` if the code cannot be parsed.
    pub fn new(
        code: String,
        script_name: &str,
        input_names: Vec<String>,
        external_functions: Vec<String>,
    ) -> Result<Self, MontyException> {
        Executor::new(code, script_name, input_names, external_functions).map(|executor| Self { executor })
    }

    /// Returns the code that was parsed to create this snapshot.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.executor.code
    }

    /// Executes the code to completion assuming not external functions or snapshotting.
    ///
    /// This is marginally faster than running with snapshotting enabled since we don't need
    /// to track the position in code, but does not allow calling of external functions.
    ///
    /// # Arguments
    /// * `inputs` - Values to fill the first N slots of the namespace
    /// * `resource_tracker` - Custom resource tracker implementation
    /// * `print` - print print implementation
    pub fn run(
        &self,
        inputs: Vec<MontyObject>,
        resource_tracker: impl ResourceTracker,
        print: &mut impl PrintWriter,
    ) -> Result<MontyObject, MontyException> {
        self.executor.run(inputs, resource_tracker, print)
    }

    /// Executes the code to completion with no resource limits, printing to stdout/stderr.
    pub fn run_no_limits(&self, inputs: Vec<MontyObject>) -> Result<MontyObject, MontyException> {
        self.run(inputs, NoLimitTracker, &mut StdPrint)
    }

    /// Serializes the runner to a binary format.
    ///
    /// The serialized data can be stored and later restored with `load()`.
    /// This allows caching parsed code to avoid re-parsing on subsequent runs.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn dump(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    /// Deserializes a runner from binary format.
    ///
    /// # Arguments
    /// * `bytes` - The serialized runner data from `dump()`
    ///
    /// # Errors
    /// Returns an error if deserialization fails.
    pub fn load(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }

    /// Starts execution with the given inputs and resource tracker, consuming self.
    ///
    /// Creates the heap and namespaces, then begins execution.
    ///
    /// For iterative execution, `start()` consumes self and returns a `RunProgress`:
    /// - `RunProgress::FunctionCall { ..., state }` - external function call, call `state.run(return_value)` to resume
    /// - `RunProgress::Complete(value)` - execution finished
    ///
    /// This enables snapshotting execution state and returning control to the host
    /// application during long-running computations.
    ///
    /// # Arguments
    /// * `inputs` - Initial input values (must match length of `input_names` from `new()`)
    /// * `resource_tracker` - Resource tracker for the execution
    /// * `print` - Writer for print output
    ///
    /// # Errors
    /// Returns `MontyException` if:
    /// - The number of inputs doesn't match the expected count
    /// - An input value is invalid (e.g., `MontyObject::Repr`)
    /// - A runtime error occurs during execution
    ///
    /// # Panics
    /// This method should not panic under normal operation. Internal assertions
    /// may panic if the VM reaches an inconsistent state (indicating a bug).
    pub fn start<T: ResourceTracker>(
        self,
        inputs: Vec<MontyObject>,
        resource_tracker: T,
        print: &mut impl PrintWriter,
    ) -> Result<RunProgress<T>, MontyException> {
        let executor = self.executor;

        // Create heap and prepare namespaces
        let mut heap = Heap::new(executor.namespace_size, resource_tracker);
        let mut namespaces = executor.prepare_namespaces(inputs, &mut heap)?;

        // Create and run VM - scope the VM borrow so we can move heap/namespaces after
        let mut vm = VM::new(&mut heap, &mut namespaces, &executor.interns, print);

        // Start execution
        let vm_result = vm.run_module(&executor.module_code);

        let vm_state = vm.check_snapshot(&vm_result);

        // Handle the result using the destructured parts
        handle_vm_result(vm_result, vm_state, executor, heap, namespaces)
    }

    /// Starts execution with caller-provided input metadata and an optional branch checker.
    ///
    /// This is the primary entry point for the interpreter layer (Phase 5), which provides:
    /// - Per-input metadata tracking (e.g., marking values as coming from specific producers)
    /// - Branch checking policy enforcement via the `BranchChecker` trait
    ///
    /// # Arguments
    /// * `inputs` - Initial input values (must match length of `input_names` from `new()`)
    /// * `input_metas` - Metadata for each input value (must match length of `inputs`)
    /// * `resource_tracker` - Resource tracker for the execution
    /// * `print` - Writer for print output
    /// * `branch_checker` - Optional policy checker for conditional branching
    ///
    /// # Errors
    /// Returns `MontyException` if:
    /// - `inputs.len() != input_metas.len()`
    /// - The number of inputs doesn't match the expected count
    /// - An input value is invalid (e.g., `MontyObject::Repr`)
    /// - A runtime error occurs during execution
    pub fn start_with_meta<T: ResourceTracker>(
        self,
        inputs: Vec<MontyObject>,
        input_metas: Vec<Metadata>,
        resource_tracker: T,
        print: &mut impl PrintWriter,
        branch_checker: Option<Box<dyn crate::bytecode::BranchChecker>>,
    ) -> Result<RunProgress<T>, MontyException> {
        if inputs.len() != input_metas.len() {
            return Err(MontyException::runtime_error(format!(
                "input count ({}) does not match metadata count ({})",
                inputs.len(),
                input_metas.len()
            )));
        }

        let executor = self.executor;

        // Create heap and prepare namespaces with caller-provided metadata
        let mut heap = Heap::new(executor.namespace_size, resource_tracker);
        let mut namespaces = executor.prepare_namespaces_with_meta(inputs, input_metas, &mut heap)?;

        // Create VM and optionally inject branch checker
        let mut vm = VM::new(&mut heap, &mut namespaces, &executor.interns, print);
        if let Some(checker) = branch_checker {
            vm.set_branch_checker(checker);
        }

        // Start execution
        let vm_result = vm.run_module(&executor.module_code);

        let vm_state = vm.check_snapshot(&vm_result);

        handle_vm_result(vm_result, vm_state, executor, heap, namespaces)
    }
}

/// Result of a single step of iterative execution.
///
/// This enum owns the execution state, ensuring type-safe state transitions.
/// - `FunctionCall` contains info about an external function call and state to resume
/// - `ResolveFutures` contains pending futures that need resolution before continuing
/// - `Complete` contains just the final value (execution is done)
///
/// # Type Parameters
/// * `T` - Resource tracker implementation (e.g., `NoLimitTracker` or `LimitedTracker`)
///
/// Serialization requires `T: Serialize + Deserialize`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "T: serde::Serialize", deserialize = "T: serde::de::DeserializeOwned"))]
pub enum RunProgress<T: ResourceTracker> {
    /// Execution paused at an external function call.
    ///
    /// The host can choose how to handle this:
    /// - **Sync resolution**: Call `state.run(return_value)` to push the result and continue
    /// - **Async resolution**: Call `state.run_pending()` to push an `ExternalFuture` and continue
    ///
    /// When using async resolution, the code continues and may `await` the future later.
    /// If the future isn't resolved when awaited, execution yields with `ResolveFutures`.
    FunctionCall {
        /// The name of the function being called.
        function_name: String,
        /// The positional arguments passed to the function.
        args: Vec<MontyObject>,
        /// The keyword arguments passed to the function (key, value pairs).
        kwargs: Vec<(MontyObject, MontyObject)>,
        /// Metadata for each positional argument.
        args_meta: Vec<Metadata>,
        /// Unique identifier for this call (used for async correlation).
        call_id: u32,
        /// The execution state that can be resumed with a return value.
        state: Snapshot<T>,
    },
    /// Execution paused for an OS-level operation.
    ///
    /// The host should execute the OS operation (filesystem, network, etc.) and
    /// call `state.run(return_value)` to provide the result and continue.
    ///
    /// This enables sandboxed execution where the interpreter never directly performs I/O.
    OsCall {
        /// The OS function to execute.
        function: OsFunction,
        /// The positional arguments for the OS function.
        args: Vec<MontyObject>,
        /// The keyword arguments passed to the function (key, value pairs).
        kwargs: Vec<(MontyObject, MontyObject)>,
        /// Metadata for each positional argument.
        args_meta: Vec<Metadata>,
        /// Unique identifier for this call (used for async correlation).
        call_id: u32,
        /// The execution state that can be resumed with a return value.
        state: Snapshot<T>,
    },
    /// All async tasks are blocked waiting for external futures to resolve.
    ///
    /// The host must resolve some or all of the pending calls before continuing.
    /// Use `state.resume(results)` to provide results for pending calls.
    ///
    /// access the pending call ids with `.pending_call_ids()`
    ResolveFutures(FutureSnapshot<T>),
    /// Execution completed with a final result and its metadata.
    Complete(MontyObject, Metadata),
}

impl<T: ResourceTracker> RunProgress<T> {
    /// Consumes the `RunProgress` and returns external function call info and state.
    ///
    /// Returns (function_name, positional_args, keyword_args, args_meta, call_id, state).
    #[must_use]
    #[expect(clippy::type_complexity)]
    pub fn into_function_call(
        self,
    ) -> Option<(
        String,
        Vec<MontyObject>,
        Vec<(MontyObject, MontyObject)>,
        Vec<Metadata>,
        u32,
        Snapshot<T>,
    )> {
        match self {
            Self::FunctionCall {
                function_name,
                args,
                kwargs,
                args_meta,
                call_id,
                state,
            } => Some((function_name, args, kwargs, args_meta, call_id, state)),
            _ => None,
        }
    }

    /// Consumes the `RunProgress` and returns the final value and its metadata.
    #[must_use]
    pub fn into_complete(self) -> Option<(MontyObject, Metadata)> {
        match self {
            Self::Complete(value, meta) => Some((value, meta)),
            _ => None,
        }
    }

    /// Consumes the `RunProgress` and returns pending futures info and state.
    ///
    /// Returns (pending_calls, state) if this is a ResolveFutures, None otherwise.
    #[must_use]
    pub fn into_resolve_futures(self) -> Option<FutureSnapshot<T>> {
        match self {
            Self::ResolveFutures(state) => Some(state),
            _ => None,
        }
    }
}

impl<T: ResourceTracker + serde::Serialize> RunProgress<T> {
    /// Serializes the execution state to a binary format.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn dump(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }
}

impl<T: ResourceTracker + serde::de::DeserializeOwned> RunProgress<T> {
    /// Deserializes execution state from binary format.
    ///
    /// # Errors
    /// Returns an error if deserialization fails.
    pub fn load(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

/// Execution state that can be resumed after an external function call.
///
/// This struct owns all runtime state and provides methods to continue execution:
/// - `run(result)`: Resume with the external function's return value (sync pattern)
/// - `run_pending()`: Resume with an `ExternalFuture` that can be awaited later (async pattern)
///
/// External function calls occur when calling a function that is not a builtin,
/// exception, or user-defined function.
///
/// # Type Parameters
/// * `T` - Resource tracker implementation
///
/// Serialization requires `T: Serialize + Deserialize`.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "T: serde::Serialize", deserialize = "T: serde::de::DeserializeOwned"))]
pub struct Snapshot<T: ResourceTracker> {
    /// The executor containing compiled code and interns.
    executor: Executor,
    /// The VM state containing stack, frames, and exception state.
    vm_state: VMSnapshot,
    /// The heap containing all allocated objects.
    heap: Heap<T>,
    /// The namespaces containing all variable bindings.
    namespaces: Namespaces,
    /// The call_id from the most recent FunctionCall that created this Snapshot.
    /// Used by `run_pending()` to push the correct `ExternalFuture`.
    pending_call_id: u32,
    /// Optional branch checker for policy enforcement, re-injected into the VM on resume.
    /// Not serialized — must be re-set by caller after deserialization.
    #[serde(skip)]
    branch_checker: Option<Box<dyn crate::bytecode::BranchChecker>>,
}

impl<T: ResourceTracker> std::fmt::Debug for Snapshot<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("executor", &self.executor)
            .field("vm_state", &self.vm_state)
            .field("heap", &"<heap>")
            .field("namespaces", &"<namespaces>")
            .field("pending_call_id", &self.pending_call_id)
            .field("branch_checker", &self.branch_checker.as_ref().map(|_| "<checker>"))
            .finish()
    }
}

#[derive(Debug)]
pub struct MontyFuture;

/// Return value or exception from an external function.
#[derive(Debug)]
pub enum ExternalResult {
    /// Continues execution with the return value and its metadata from the external function.
    Return(MontyObject, Metadata),
    /// Continues execution with the exception raised by the external function.
    Error(MontyException),
    /// Pending future - when the external function is a coroutine.
    Future,
}

impl ExternalResult {
    /// Creates a Return with explicit metadata.
    pub fn return_with_meta(obj: MontyObject, meta: Metadata) -> Self {
        Self::Return(obj, meta)
    }
}

impl From<MontyObject> for ExternalResult {
    fn from(value: MontyObject) -> Self {
        Self::Return(value, Metadata::default())
    }
}

impl From<MontyException> for ExternalResult {
    fn from(exception: MontyException) -> Self {
        Self::Error(exception)
    }
}

impl From<MontyFuture> for ExternalResult {
    fn from(_: MontyFuture) -> Self {
        Self::Future
    }
}

impl<T: ResourceTracker> Snapshot<T> {
    /// Sets the branch checker for policy enforcement on resume.
    ///
    /// The branch checker is not serialized, so it must be re-set by the caller
    /// after deserialization or before calling `run()` on a snapshot that needs
    /// branch checking.
    pub fn set_branch_checker(&mut self, checker: Box<dyn crate::bytecode::BranchChecker>) {
        self.branch_checker = Some(checker);
    }

    /// Continues execution with the return value or exception from the external function.
    ///
    /// Consumes self and returns the next execution progress.
    ///
    /// # Arguments
    /// * `result` - The return value or exception from the external function
    /// * `print` - The print writer to use for output
    ///
    /// # Panics
    /// This method should not panic under normal operation. Internal assertions
    /// may panic if the VM reaches an inconsistent state (indicating a bug).
    pub fn run(
        mut self,
        result: impl Into<ExternalResult>,
        print: &mut impl PrintWriter,
    ) -> Result<RunProgress<T>, MontyException> {
        let ext_result = result.into();

        // Restore the VM from the snapshot
        let mut vm = VM::restore(
            self.vm_state,
            &self.executor.module_code,
            &mut self.heap,
            &mut self.namespaces,
            &self.executor.interns,
            print,
        );

        // Re-inject the branch checker if one was set
        if let Some(checker) = self.branch_checker.take() {
            vm.set_branch_checker(checker);
        }

        // Convert return value or exception before creating VM (to avoid borrow conflicts)
        let vm_result = match ext_result {
            ExternalResult::Return(obj, meta) => vm.resume(obj, meta),
            ExternalResult::Error(exc) => vm.resume_with_exception(exc.into()),
            ExternalResult::Future => {
                // Get the call_id and ext_function_id that were stored when this Snapshot was created
                let call_id = CallId::new(self.pending_call_id);

                // Store pending call data in the scheduler so we can track the creator task
                // and ignore results if the task is cancelled
                vm.add_pending_call(call_id);

                // Push the ExternalFuture value onto the stack
                // This allows the code to continue and potentially await this future later
                vm.push(Value::ExternalFuture(call_id));
                vm.push_meta(Metadata::default());

                // Continue execution
                vm.run()
            }
        };

        let vm_state = vm.check_snapshot(&vm_result);

        // Handle the result using the destructured parts
        handle_vm_result(vm_result, vm_state, self.executor, self.heap, self.namespaces)
    }

    /// Continues execution by pushing an ExternalFuture instead of a concrete value.
    ///
    /// This is the async resolution pattern: instead of providing the result immediately,
    /// the host calls this method to continue execution with a pending future. The code
    /// can then `await` this future later.
    ///
    /// If the code awaits the future before it's resolved, execution will yield with
    /// `RunProgress::ResolveFutures`. The host can then provide the result via
    /// `FutureSnapshot::resume()`.
    ///
    /// # Arguments
    /// * `print` - Writer for print output
    ///
    /// # Returns
    /// The next execution progress - may be another `FunctionCall`, `ResolveFutures`, or `Complete`.
    ///
    /// # Panics
    /// Panics if the VM reaches an inconsistent state (indicating a bug in the interpreter).
    pub fn run_pending(self, print: &mut impl PrintWriter) -> Result<RunProgress<T>, MontyException> {
        self.run(MontyFuture, print)
    }
}

/// Execution state paused while waiting for external future results.
///
/// Unlike `Snapshot` (used for sync external calls), `FutureSnapshot` supports
/// incremental resolution - you can provide partial results and Monty will
/// continue running until all tasks are blocked again.
///
/// # Type Parameters
/// * `T` - Resource tracker implementation
///
/// Serialization requires `T: Serialize + Deserialize`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "T: serde::Serialize", deserialize = "T: serde::de::DeserializeOwned"))]
pub struct FutureSnapshot<T: ResourceTracker> {
    /// The executor containing compiled code and interns.
    executor: Executor,
    /// The VM state containing stack, frames, and exception state.
    vm_state: VMSnapshot,
    /// The heap containing all allocated objects.
    heap: Heap<T>,
    /// The namespaces containing all variable bindings.
    namespaces: Namespaces,
    /// The pending call_ids that this snapshot is waiting on.
    /// Used to validate that resume() only receives known call_ids.
    pending_call_ids: Vec<u32>,
}

impl<T: ResourceTracker> FutureSnapshot<T> {
    pub fn pending_call_ids(&self) -> &[u32] {
        &self.pending_call_ids
    }

    /// Resumes execution with results for some or all pending futures.
    ///
    /// **Incremental resolution**: You don't need to provide all results at once.
    /// If you provide a partial list, Monty will:
    /// 1. Mark those futures as resolved
    /// 2. Unblock any tasks waiting on those futures
    /// 3. Continue running until all tasks are blocked again
    /// 4. Return `ResolveFutures` with the remaining pending calls
    ///
    /// This allows the host to resolve futures as they complete, rather than
    /// waiting for all of them.
    ///
    /// # Arguments
    /// * `results` - List of (call_id, result) pairs. Can be a subset of pending calls.
    /// * `print` - Writer for print output
    ///
    /// # Returns
    /// * `RunProgress::ResolveFutures` - More futures need resolution
    /// * `RunProgress::FunctionCall` - VM hit another external call
    /// * `RunProgress::Complete` - All tasks completed successfully
    /// * `Err(MontyException)` - An unhandled exception occurred
    ///
    /// # Errors
    /// Returns `Err(MontyException)` if any call_id in `results` is not in the pending set.
    ///
    /// # Panics
    /// Panics if the VM state cannot be snapshotted (internal error).
    pub fn resume(
        self,
        results: Vec<(u32, ExternalResult)>,
        print: &mut impl PrintWriter,
    ) -> Result<RunProgress<T>, MontyException> {
        use crate::exception_private::RunError;

        // Destructure self to avoid partial move issues
        let Self {
            executor,
            vm_state,
            mut heap,
            mut namespaces,
            pending_call_ids,
        } = self;

        // Validate that all provided call_ids are in the pending set before restoring VM
        let invalid_call_id = results
            .iter()
            .find(|(call_id, _)| !pending_call_ids.contains(call_id))
            .map(|(call_id, _)| *call_id);

        // Restore the VM from the snapshot (must happen before any error return to clean up properly)
        let mut vm = VM::restore(
            vm_state,
            &executor.module_code,
            &mut heap,
            &mut namespaces,
            &executor.interns,
            print,
        );

        // Now check for invalid call_ids after VM is restored
        if let Some(call_id) = invalid_call_id {
            vm.cleanup();
            return Err(MontyException::runtime_error(format!(
                "unknown call_id {call_id}, expected one of: {pending_call_ids:?}"
            )));
        }

        for (call_id, ext_result) in results {
            match ext_result {
                // Resolve successful futures in the scheduler
                ExternalResult::Return(obj, _meta) => vm.resolve_future(call_id, obj).map_err(|e| {
                    MontyException::runtime_error(format!("Invalid return type for call {call_id}: {e}"))
                })?,
                // Fail futures that returned errors
                ExternalResult::Error(exc) => vm.fail_future(call_id, RunError::from(exc)),
                // do nothing, same as not returning this id
                ExternalResult::Future => {}
            }
        }

        // Check if the current task has failed (e.g., external future failed for a gather).
        // If so, propagate the error immediately without continuing execution.
        if let Some(error) = vm.take_failed_task_error() {
            vm.cleanup();
            return Err(error.into_python_exception(&executor.interns, &executor.code));
        }

        // Push resolved value for main task if it was blocked.
        // Returns true if the main task was unblocked and a value was pushed.
        let main_task_ready = vm.prepare_main_task_after_resolve();

        // Load a ready task if frames are empty (e.g., gather completed while
        // tasks were running and we yielded with no frames)
        let loaded_task = match vm.load_ready_task_if_needed() {
            Ok(loaded) => loaded,
            Err(e) => {
                vm.cleanup();
                return Err(e.into_python_exception(&executor.interns, &executor.code));
            }
        };

        // Check if we can continue execution.
        // If the main task wasn't unblocked, no task was loaded, and there are still frames
        // (meaning the main task is still blocked waiting for futures), we need to return
        // ResolveFutures without calling vm.run().
        if !main_task_ready && !loaded_task {
            let pending_call_ids = vm.get_pending_call_ids();
            if !pending_call_ids.is_empty() {
                let vm_state = vm.snapshot();
                let pending_call_ids: Vec<u32> = pending_call_ids.iter().map(|id| id.raw()).collect();
                return Ok(RunProgress::ResolveFutures(Self {
                    executor,
                    vm_state,
                    heap,
                    namespaces,
                    pending_call_ids,
                }));
            }
        }

        // Continue execution
        let result = vm.run();

        let vm_state = vm.check_snapshot(&result);

        // Handle the result using the destructured parts
        handle_vm_result(result, vm_state, executor, heap, namespaces)
    }
}

/// Handles a FrameExit result and converts it to RunProgress for FutureSnapshot.
///
/// This is a standalone function to avoid partial move issues when destructuring FutureSnapshot.
fn handle_vm_result<T: ResourceTracker>(
    result: RunResult<FrameExit>,
    vm_state: Option<VMSnapshot>,
    executor: Executor,
    mut heap: Heap<T>,
    namespaces: Namespaces,
) -> Result<RunProgress<T>, MontyException> {
    macro_rules! new_snapshot {
        ($call_id: expr) => {
            Snapshot {
                executor,
                vm_state: vm_state.expect("snapshot should exist for ExternalCall"),
                heap,
                namespaces,
                pending_call_id: $call_id.raw(),
                branch_checker: None,
            }
        };
    }

    match result {
        Ok(FrameExit::Return(value, meta)) => {
            let obj = MontyObject::new(value, &mut heap, &executor.interns);
            Ok(RunProgress::Complete(obj, meta))
        }
        Ok(FrameExit::ExternalCall {
            ext_function_id,
            args,
            args_meta,
            call_id,
        }) => {
            let function_name = executor.interns.get_external_function_name(ext_function_id);
            let (args_py, kwargs_py) = args.into_py_objects(&mut heap, &executor.interns);
            // Defensively align args_meta length with args_py length.
            // Normally these match 1:1, but handle edge cases gracefully.
            let args_meta = if args_meta.len() == args_py.len() {
                args_meta
            } else if args_meta.is_empty() {
                vec![Metadata::default(); args_py.len()]
            } else {
                let merged = Metadata::merge_all(args_meta.iter());
                vec![merged; args_py.len()]
            };

            Ok(RunProgress::FunctionCall {
                function_name,
                args: args_py,
                kwargs: kwargs_py,
                args_meta,
                call_id: call_id.raw(),
                state: new_snapshot!(call_id),
            })
        }
        Ok(FrameExit::OsCall {
            function,
            args,
            args_meta,
            call_id,
        }) => {
            let (args_py, kwargs_py) = args.into_py_objects(&mut heap, &executor.interns);
            // Defensively align args_meta length with args_py length.
            let args_meta = if args_meta.len() == args_py.len() {
                args_meta
            } else if args_meta.is_empty() {
                vec![Metadata::default(); args_py.len()]
            } else {
                let merged = Metadata::merge_all(args_meta.iter());
                vec![merged; args_py.len()]
            };

            Ok(RunProgress::OsCall {
                function,
                args: args_py,
                kwargs: kwargs_py,
                args_meta,
                call_id: call_id.raw(),
                state: new_snapshot!(call_id),
            })
        }
        Ok(FrameExit::ResolveFutures(pending_call_ids)) => {
            let pending_call_ids: Vec<u32> = pending_call_ids.iter().map(|id| id.raw()).collect();
            Ok(RunProgress::ResolveFutures(FutureSnapshot {
                executor,
                vm_state: vm_state.expect("snapshot should exist for ResolveFutures"),
                heap,
                namespaces,
                pending_call_ids,
            }))
        }
        Err(err) => {
            Err(err.into_python_exception(&executor.interns, &executor.code))
        }
    }
}

/// Lower level interface to parse code and run it to completion.
///
/// This is an internal type used by [`MontyRun`]. It stores the compiled bytecode and source code
/// for error reporting.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Executor {
    /// Number of slots needed in the global namespace.
    namespace_size: usize,
    /// Compiled bytecode for the module.
    module_code: Code,
    /// Interned strings used for looking up names and filenames during execution.
    interns: Interns,
    /// IDs to create values to inject into the the namespace to represent external functions.
    external_function_ids: Vec<ExtFunctionId>,
    /// Source code for error reporting (extracting preview lines for tracebacks).
    code: String,
    /// Estimated heap capacity for pre-allocation on subsequent runs.
    /// Uses AtomicUsize for thread-safety (required by PyO3's Sync bound).
    heap_capacity: AtomicUsize,
}

impl Clone for Executor {
    fn clone(&self) -> Self {
        Self {
            namespace_size: self.namespace_size,
            module_code: self.module_code.clone(),
            interns: self.interns.clone(),
            external_function_ids: self.external_function_ids.clone(),
            code: self.code.clone(),
            heap_capacity: AtomicUsize::new(self.heap_capacity.load(Ordering::Relaxed)),
        }
    }
}

impl Executor {
    /// Creates a new executor with the given code, filename, input names, and external functions.
    fn new(
        code: String,
        script_name: &str,
        input_names: Vec<String>,
        external_functions: Vec<String>,
    ) -> Result<Self, MontyException> {
        let parse_result = parse(&code, script_name).map_err(|e| e.into_python_exc(script_name, &code))?;
        let prepared = prepare(parse_result, input_names, &external_functions)
            .map_err(|e| e.into_python_exc(script_name, &code))?;

        // Incrementing order matches the indexes used in intern::Interns::get_external_function_name
        let external_function_ids = (0..external_functions.len()).map(ExtFunctionId::new).collect();

        // Create interns with empty functions (functions will be set after compilation)
        let mut interns = Interns::new(prepared.interner, Vec::new(), external_functions);

        // Compile the module to bytecode, which also compiles all nested functions
        let namespace_size_u16 = u16::try_from(prepared.namespace_size).expect("module namespace size exceeds u16");
        let compile_result = Compiler::compile_module(&prepared.nodes, &interns, namespace_size_u16)
            .map_err(|e| e.into_python_exc(script_name, &code))?;

        // Set the compiled functions in the interns
        interns.set_functions(compile_result.functions);

        Ok(Self {
            namespace_size: prepared.namespace_size,
            module_code: compile_result.code,
            interns,
            external_function_ids,
            code,
            heap_capacity: AtomicUsize::new(prepared.namespace_size),
        })
    }

    /// Executes the code with a custom resource tracker.
    ///
    /// This provides full control over resource tracking and garbage collection
    /// scheduling. The tracker is called on each allocation and periodically
    /// during execution to check time limits and trigger GC.
    ///
    /// # Arguments
    /// * `inputs` - Values to fill the first N slots of the namespace
    /// * `resource_tracker` - Custom resource tracker implementation
    /// * `print` - Print implementation for print() output
    fn run(
        &self,
        inputs: Vec<MontyObject>,
        resource_tracker: impl ResourceTracker,
        print: &mut impl PrintWriter,
    ) -> Result<MontyObject, MontyException> {
        let heap_capacity = self.heap_capacity.load(Ordering::Relaxed);
        let mut heap = Heap::new(heap_capacity, resource_tracker);
        let mut namespaces = self.prepare_namespaces(inputs, &mut heap)?;

        // Create and run VM
        let mut vm = VM::new(&mut heap, &mut namespaces, &self.interns, print);
        let frame_exit_result = vm.run_module(&self.module_code);

        // Clean up VM state before it goes out of scope
        vm.cleanup();

        if heap.size() > heap_capacity {
            self.heap_capacity.store(heap.size(), Ordering::Relaxed);
        }

        frame_exit_to_object(frame_exit_result, &mut heap, &self.interns)
            .map_err(|e| e.into_python_exception(&self.interns, &self.code))
    }

    /// Prepares the namespace namespaces for execution.
    ///
    /// Converts each `MontyObject` input to a `Value`, allocating on the heap if needed.
    /// Returns the prepared Namespaces or an error if there are too many inputs or invalid input types.
    fn prepare_namespaces(
        &self,
        inputs: Vec<MontyObject>,
        heap: &mut Heap<impl ResourceTracker>,
    ) -> Result<Namespaces, MontyException> {
        let Some(extra) = self
            .namespace_size
            .checked_sub(self.external_function_ids.len() + inputs.len())
        else {
            return Err(MontyException::runtime_error("too many inputs for namespace"));
        };
        // register external functions in the namespace first, matching the logic in prepare
        let mut namespace: Vec<Value> = Vec::with_capacity(self.namespace_size);
        for f_id in &self.external_function_ids {
            namespace.push(Value::ExtFunction(*f_id));
        }
        // Convert each MontyObject to a Value, propagating any invalid input errors
        for input in inputs {
            namespace.push(
                input
                    .to_value(heap, &self.interns)
                    .map_err(|e| MontyException::runtime_error(format!("invalid input type: {e}")))?,
            );
        }
        if extra > 0 {
            namespace.extend((0..extra).map(|_| Value::Undefined));
        }
        // Initialize parallel metadata: all slots start with clean (default) metadata.
        // Input metadata will be provided by the caller in Phase 5 (interpreter layer).
        let metadata = vec![security_compass_meta::Metadata::default(); namespace.len()];
        Ok(Namespaces::new(namespace, metadata))
    }

    /// Prepares namespaces with caller-provided metadata for input variables.
    ///
    /// This mirrors `prepare_namespaces()` but accepts metadata for each input variable
    /// instead of using `Metadata::default()` for all slots. The metadata layout is:
    /// - External function slots → `Metadata::default()` (internal VM objects)
    /// - Input variable slots → caller-provided `input_metas[i]`
    /// - Remaining uninitialized slots → `Metadata::default()`
    ///
    /// # Precondition
    /// `inputs.len() == input_metas.len()` (validated by caller)
    fn prepare_namespaces_with_meta(
        &self,
        inputs: Vec<MontyObject>,
        input_metas: Vec<Metadata>,
        heap: &mut Heap<impl ResourceTracker>,
    ) -> Result<Namespaces, MontyException> {
        let Some(extra) = self
            .namespace_size
            .checked_sub(self.external_function_ids.len() + inputs.len())
        else {
            return Err(MontyException::runtime_error("too many inputs for namespace"));
        };

        // Build value namespace
        let mut namespace: Vec<Value> = Vec::with_capacity(self.namespace_size);
        for f_id in &self.external_function_ids {
            namespace.push(Value::ExtFunction(*f_id));
        }
        for input in inputs {
            namespace.push(
                input
                    .to_value(heap, &self.interns)
                    .map_err(|e| MontyException::runtime_error(format!("invalid input type: {e}")))?,
            );
        }
        if extra > 0 {
            namespace.extend((0..extra).map(|_| Value::Undefined));
        }

        // Build parallel metadata with caller-provided input metadata
        let mut metadata: Vec<Metadata> = Vec::with_capacity(namespace.len());
        // External function slots get default metadata
        for _ in &self.external_function_ids {
            metadata.push(Metadata::default());
        }
        // Input variable slots get caller-provided metadata
        for meta in input_metas {
            metadata.push(meta);
        }
        // Remaining uninitialized slots get default metadata
        if extra > 0 {
            metadata.extend((0..extra).map(|_| Metadata::default()));
        }

        Ok(Namespaces::new(namespace, metadata))
    }
}

fn frame_exit_to_object(
    frame_exit_result: RunResult<FrameExit>,
    heap: &mut Heap<impl ResourceTracker>,
    interns: &Interns,
) -> RunResult<MontyObject> {
    match frame_exit_result? {
        FrameExit::Return(return_value, _meta) => Ok(MontyObject::new(return_value, heap, interns)),
        FrameExit::ExternalCall { ext_function_id, .. } => {
            let function_name = interns.get_external_function_name(ext_function_id);
            Err(ExcType::not_implemented(format!(
                "External function '{function_name}' not implemented with standard execution"
            ))
            .into())
        }
        FrameExit::OsCall { function, .. } => Err(ExcType::not_implemented(format!(
            "OS function '{function}' not implemented with standard execution"
        ))
        .into()),
        FrameExit::ResolveFutures(_) => {
            Err(ExcType::not_implemented("async futures not supported by standard execution.").into())
        }
    }
}

