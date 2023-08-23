// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// DISTRIBUTION A. Approved for public release; distribution unlimited.
// OPSEC #4584.

use std::error::Error;

pub(crate) struct LifecycleMachine<S> {
    state: S,
    transitions: Transitions,
}

// struct Transitions {
//     activate: fn(Inactive) -> Result<Active, Box<dyn Error>>,
//     cleanup: fn(Inactive) -> Result<Unconfigured, Box<dyn Error>>,
//     configure: fn(Unconfigured) -> Result<Inactive, Box<dyn Error>>,
//     deactivate: fn(Active) -> Result<Inactive, Box<dyn Error>>,
// }

////////////////////
// Primary States //
////////////////////

pub(crate) enum PrimaryState {
    Unconfigured(LifecycleMachine<Unconfigured>),
    Inactive(LifecycleMachine<Inactive>),
    Active(LifecycleMachine<Active>),
    Finalized(LifecycleMachine<Finalized>),
}

/// This is the life cycle state the node is in immediately after being instantiated. This is
/// alse the state in which a node may be returned to after an error has happened. In this
/// state there is expected to be no stored state.
///
/// # Valid transitions out:
/// - The node may transition to the [`Inactive`] state via the [`Transitions::Configure`]
/// transition.
/// - The node may transition to the [`Finalized`] state via the [`Transitions::Shutdown`]
/// transition.
pub(crate) struct Unconfigured {
    shutdown: fn(Self) -> ShuttingDown,
}

/// This state represents a node that is not currently performing any processing.
///
/// The main purpose of this state is to allow a node to be (re-)configured (changing
/// configuration parameters, adding and removing topic publications/subscriptions, etc)
/// without altering its behavior while it is running.
///
/// While in this state, the node will not recieve any execution time to read topics,
/// perform processing of data, respond to functional service requests, etc.
///
/// In the inactive state, any data that arrives on managed topics will not be read and/or
/// processed. Data retention will be subject to the configured QoS policy for the topic.
///
/// Any managed service requests to a node in the inactive state will not be answered (to the
/// caller, they will fail immediately).
///
/// # Valid transitions out:
/// - The node may transition to the [`Finalized`] state via the [`Transitions::Shutdown`]
/// transition.
/// - The node may transition to the [`Unconfigured`] state via the [`Transitions::Cleanup`]
/// transition.
/// - The node may transition to the [`Active`] state via the [`Transitions::Activate`]
/// transition
pub(crate) struct Inactive {
    shutdown: fn(Self) -> ShuttingDown,
}

/// This is the main state of the node's life cycle. While in this state, the node performs any
/// processing, responds to service requests, reads and processes data, produces output, etc.
///
/// If an error that cannot be handled by the node/system occurs in this state, the node will
/// transition to [`ErrorProcessing`].
///
/// # Valid transitions out:
/// - The node may transition to the [`Inactive`] state via the [`Transitions::Deactivate`]
/// transition.
/// - The node may transition to the [`Finalized`] state via the [`Transitions::Shutdown`]
/// transition.
pub(crate) struct Active {
    shutdown: fn(Self) -> ShuttingDown,
    on_error: fn(Self) -> ErrorProcessing,
}

/// This is the state in which the node ends in immediately before being destroyed. This state is
/// always terminal - the only transition from here is to be destroyed.
///
/// This state exists to support debugging and introspection. A node which has failed will remain
/// visible to system introspection and may be potentially introspectable by debugging tools
/// instead of directly destructing. If a node is being launched in a respawn loop or has known
/// reasons for cycling, it is expected that the supervisory process will have a policy to
/// automatically destroy and recreate the node.
///
/// # Valid transitions out:
/// - The node may be deallocated via the [`Transitions::Destroy`] transition.
pub(crate) struct Finalized {}

///////////////////////
// Transition States //
///////////////////////
pub(crate) enum Transitions {
    Create,
    Configure,
    Cleanup,
    Activate,
    Deactivate,
    Shutdown,
    Destroy,
}

pub(crate) enum TransitionState {
    Configuring(LifecycleMachine<Configuring>),
    CleaningUp(LifecycleMachine<CleaningUp>),
    ShuttingDown(LifecycleMachine<ShuttingDown>),
    Activating(LifecycleMachine<Activating>),
    Deactivating(LifecycleMachine<Deactivating>),
    ErrorProcessing(LifecycleMachine<ErrorProcessing>),
}

/// In this transition state, the node's `onConfigure` callback will be called to allow the node
/// to load its configuration and conduct any required setup.
///
/// The configuration of a node will typically involve those tasts that must be performed once
/// during the node's life time, such as obtaining permanent memory buffers and setting up topic
/// publications/subscriptions that do not change.
///
/// The node uses this to set up any resources it must hold throughout its life (irrespective of
/// if it is active or inactive). As examples, such resources may include topic publicatons and
/// subscriptions, memory that is held continuously, and initializing configuration parameters.
///
/// # Valid transitions out:
/// - If the `onConfigure` callback succeeds, the node will transition to [`Inactive`]
/// - If the `onConfigure` callback failes, the node will either transition back to [`Unconfigured`]
/// or to [`ErrorProcessing`]
pub(crate) struct Configuring {}

/// In this transition state, the node's callback `onCleanup` will be called. This method is
/// expected to clear all state and return the node to a functionally equivalent state as when it
/// was first created. If the cleanup cannot be successfully achieved it will transition to
/// [`ErrorProcessing`].
///
/// # Valid transitions out:
/// - If the `onCleanup` callback succeeds the node will transition to [`Unconfigured`].
/// - If the `onCleanup` callback raises or results in any other return code the node will
/// transition to [`ErrorProcessing`].
pub(crate) struct CleaningUp {}

/// In this transition state, the callbacl `onShutdown` will be executed. This method is expected
/// to do any cleanup necessary before destruction. It may be entered from any Primary State
/// except [`Finalized`], the originating state will be passed to the method.
///
/// # Valid transitions out:
/// - If the `onShutdown` callback succeeds, the node will transition to [`Finalized`].
/// - If the `onShutdown` callback raises or results in any other return code, the node will
/// transition to [`ErrorProcessing`].
pub(crate) struct ShuttingDown {}

/// In this transition state, the callback `onActivate` will be executed. This method is expected
/// to do any final preparations to start executing. This may include acquiring resources that are
/// only held while the node is actually active, such as access to hardware. Ideally, no
/// preparation that requires significant time (such as lengthy hardware initialization) should be
/// performed in this callback.
///
/// # Valid transitions out:
/// - If the `onActivate` callback succeeds, the node will transition to [`Active`].
/// - If the `onActiveate` callback raises or results in any other return code, the node will
/// transition to [`ErrorProcessing`].
pub(crate) struct Activating {}

/// In this transition state, the callback `onDeactivate` will be executed. This method is expected
/// to do any cleanup to start executing, and should reverse the `onActivate` changes.
///
/// # Valid transitions out:
/// - If the `onDeactivate` callback succeeds, the node will transition to [`Inactive`].
/// - If the `onDeactivate` callback raises or results in any other return code, the node will
/// transition to [`ErrorProcessing`].
pub(crate) struct Deactivating {}

/// This transition state is where any error can be cleaned up. It is possible to enter this state
/// from any state where user code will be executed. If error handling is successfully completed,
/// the node can return to [`Unconfigured`]. If a full cleanup is not possible, it must fail and
/// the node will transition to [`Finalized`] in preparation for destruction.
///
/// Transitions to [`ErrorProcessing`] may be caused by error return codes in callbacks, as well
/// as methods within a callback or an uncaught exception.
///
/// # Valid transitions out:
/// - If the `onError` callback succeeds the node will transition to [`Unconfigured`]. It is
/// expected that the `onError` will clean up all state from any previous state. As such, if
/// entered from [`Active`], it must provide the cleanup of both `onDeactivate` and `onCleanup` to
/// return success.
/// - If the `onShutdown` callback raises or results in any other result code, the node will transition to [`Finalized`].
pub(crate) struct ErrorProcessing {}
