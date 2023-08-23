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
use std::ffi::CString;
use std::sync::{Arc, Mutex};

use rosidl_runtime_rs::{RmwMessage, Service};

use crate::vendor::lifecycle_msgs;
use crate::{rcl_bindings::*, Context, RclrsError, ToResult, resolve_parameter_overrides};
use crate::lifecycle_node::{call_string_getter_with_handle, LifecycleNode};

use super::LifecycleCallback;

/// A builder for creating a [`LifecycleNode`][1].
/// 
/// The builder pattern allows selectively setting some fields, and leaving all others at their default values.
/// This struct instance can be created via [`LifecycleNode::builder()`][2].
/// 
/// 
/// [1]: crate::LifecycleNode
/// [2]: crate::LifecycleNode::builder
pub struct LifecycleNodeBuilder {
    context: Arc<Mutex<rcl_context_t>>,
    name: String,
    namespace: String,
    use_global_arguments: bool,
    arguments: Vec<String>,
    enable_rosout: bool,
    on_activate: Option<LifecycleCallback>,
    on_cleanup: Option<LifecycleCallback>,
    on_configure: Option<LifecycleCallback>,
    on_deactivate: Option<LifecycleCallback>,
    on_error: Option<LifecycleCallback>,
    on_shutdown: Option<LifecycleCallback>,
    enable_communication_interface: bool,
}

impl LifecycleNodeBuilder {

    /// Creates a builder for a lifecycle node with the given name.
    /// 
    /// See the [`Node` docs][1] for general information on node names
    /// 
    /// # Rules for valid node names
    /// 
    /// The rules for a valid node name are checked by the [`rmw_validate_node_name()`][2]
    /// function. They are:
    /// - Must contain only the `a-z`, `A-Z`, `0-9`, and `_` characters
    /// - Must not be empty and not be longer than `RMW_NODE_NAME_MAX_NAME_LENGTH`
    /// - Must not start with a number
    /// 
    /// Note that node name validation is delayed until [`LifecycleNodeBuilder::build()`][3].
    /// 
    /// [1]: crate::Node#naming
    /// [2]: https://docs.ros2.org/latest/api/rmw/validate__node__name_8h.html#a5690a285aed9735f89ef11950b6e39e3
    /// [3]: LifecycleNodeBuilder::build
    pub fn new(context: &Context, name: &str) -> LifecycleNodeBuilder {
        LifecycleNodeBuilder {
            context: context.rcl_context_mtx.clone(),
            name: name.to_string(),
            namespace: "/".to_string(),
            use_global_arguments: true,
            arguments: vec![],
            enable_rosout: true,
            on_activate: None,
            on_cleanup: None,
            on_configure: None,
            on_deactivate: None,
            on_error: None,
            on_shutdown: None,
            enable_communication_interface: true,
        }
    }

    /// Sets the node namespace.
    /// 
    /// See the [`Node` docs][1] for general information on namespaces.
    /// 
    /// # Rules for valid namespaces
    /// 
    /// The rules for a valid node namespace are based on the [rules for a valid topic][2]
    /// and are checked by the [`rmw_validate_namespace()`][3] function. However, a namespace
    /// without a leading forward slash is automatically changed to have a leading forward slash
    /// before it is checked with this function.
    /// 
    /// Thus, the effective rules are:
    /// - Must contain only the `a-z`, `A-Z`, `0-9`, `_`, and `/` characters
    /// - Must not have a number at the beginning, or after a `/`
    /// - Must not contain two or more `/` characters in a row
    /// - Must not have a `/` character at the end, except if `/` is the full namespace
    /// 
    /// Note that namespace validation is delayed until [`NodeBuilder::build()`][4].
    /// 
    /// [1]: crate::Node#naming
    /// [2]: http://design.ros2.org/articles/topic_and_service_names.html
    /// [3]: https://docs.ros2.org/latest/api/rmw/validate__namespace_8h.html#a043f17d240cf13df01321b19a469ee49
    /// [4]: NodeBuilder::build
    pub fn namespace(mut self, namespace: &str) -> Self {
        self.namespace = namespace.to_string();
        self
    }

    /// Enables or disables using global arguments.
    /// 
    /// The "global" arguments are those used in [creating the context][1].
    /// 
    /// [1]: crate::Context::new
    pub fn use_global_arguments(mut self, enable: bool) -> Self {
        self.use_global_arguments = enable;
        self
    }

    /// Sets node-specific command line arguments.
    /// 
    /// These arguments are parsed the same way as those for [`Context::new()`][1].
    /// However, the node-specific command line arguments have higher precedence than the arguments
    /// used in creating the context.
    /// 
    /// For more details about command line arguments, see [here][2].
    /// 
    /// [1]: crate::Context::new
    /// [2]: https://design.ros2.org/articles/ros_command_line_arguments.html
    pub fn arguments(mut self, arguments: impl IntoIterator<Item = String>) -> Self {
        self.arguments = arguments.into_iter().collect();
        self
    }

    /// Enables or disables logging to rosout.
    /// 
    /// When enabled, log messages are published to the `/rosout` topic in addition to
    /// standard output.
    /// 
    /// This option is currently unused in `rclrs`
    pub fn enable_rosout(mut self, enable: bool) -> Self {
        self.enable_rosout = enable;
        self
    }

    pub fn build(self) -> Result<LifecycleNode, Box<dyn Error>> {
        let node_name =
            CString::new(self.name.as_str()).map_err(|err| RclrsError::StringContainsNul {
                err,
                s: self.name.clone(),
            })?;
        let node_namespace =
            CString::new(self.namespace.as_str()).map_err(|err| RclrsError::StringContainsNul {
                err,
                s: self.namespace.clone()
            })?;
        let rcl_node_options = self.create_rcl_node_options()?;
        let rcl_context = &mut *self.context.lock().unwrap();
        
        // Safety: Getting a zero-initialized value is always safe.
        let mut rcl_node = unsafe { rcl_get_zero_initialized_node() };
        unsafe {
            // SAFETY: The rcl_node is zero-initialized as expected by this function.
            // The strings and node options are copied by this function, so we don't need
            // to keep them alive.
            // The rcl_context has to be kept alive because it is co-owned by the node.
            rcl_node_init(
                &mut rcl_node,
                node_name.as_ptr(),
                node_namespace.as_ptr(),
                rcl_context,
                &rcl_node_options,
            ).ok()?;
        }

        let _parameter_map = unsafe {
            let fqn = call_string_getter_with_handle(&rcl_node, rcl_node_get_fully_qualified_name);
            resolve_parameter_overrides(&fqn,
                &rcl_node_options.arguments,
                &rcl_context.global_arguments,
            )?
        };
        let rcl_node_mtx = Arc::new(Mutex::new(rcl_node));
        
        let on_activate = self.on_activate.ok_or("The \"on_activate\" transition is required for building")?;
        let on_cleanup = self.on_cleanup.ok_or("The \"on_cleanup\" transition is required for building.")?;
        let on_configure = self.on_configure.ok_or("The \"on_configure\" transition is required for building.")?;
        let on_deactivate = self.on_deactivate.ok_or("The \"on_deactivate\" transition is required for building.")?;
        let on_error = self.on_error.ok_or("The \"on_error\" transition is required for building.")?;
        let on_shutdown = self.on_shutdown.ok_or("The \"on_shutdown\" transition is required for building.")?;

        // SAFETY: Getting a zero-initialized state machine is always safe
        let state_machine = Arc::new(Mutex::new(unsafe { rcl_lifecycle_get_zero_initialized_state_machine() }));
        // SAFETY: Getting the default state machine options is always safe
        let mut state_machine_options = unsafe { rcl_lifecycle_get_default_state_machine_options() };
        state_machine_options.enable_com_interface = self.enable_communication_interface;
        // SAFETY: Getting the default allocator is always safe
        // TODO(jhdcs): If we ever allow the use of a non-default allocator, this will need to change
        state_machine_options.allocator = unsafe { rcutils_get_default_allocator() };

        // SAFETY: Initializing the lifecycle state machine is always safe
        unsafe {
            let mut state_machine_mtx = state_machine.lock().unwrap();
            let mut rcl_node_mtx = rcl_node_mtx.lock().unwrap();
            rcl_lifecycle_state_machine_init(
                &mut *state_machine_mtx,
                &mut *rcl_node_mtx,
                <lifecycle_msgs::msg::TransitionEvent as rosidl_runtime_rs::Message>::RmwMsg::get_type_support() as *const rosidl_message_type_support_t,
                <lifecycle_msgs::srv::ChangeState as rosidl_runtime_rs::Service>::get_type_support() as *const rosidl_service_type_support_t,
                <lifecycle_msgs::srv::GetState as rosidl_runtime_rs::Service>::get_type_support() as *const rosidl_service_type_support_t,
                lifecycle_msgs::srv::GetAvailableStates::get_type_support() as *const rosidl_service_type_support_t,
                lifecycle_msgs::srv::GetAvailableTransitions::get_type_support() as *const rosidl_service_type_support_t,
                lifecycle_msgs::srv::GetAvailableTransitions::get_type_support() as *const rosidl_service_type_support_t,
                &state_machine_options
            ).ok()?;
        }

        if self.enable_communication_interface {
            // Change State
            {

            }
        }

        Ok(LifecycleNode {
            rcl_node_mtx,
            rcl_context_mtx: self.context.clone(),
            clients: vec![],
            guard_conditions: vec![],
            services: vec![],
            subscriptions: vec![],
            on_activate: Mutex::new(on_activate),
            on_cleanup: Mutex::new(on_cleanup),
            on_configure: Mutex::new(on_configure),
            on_deactivate: Mutex::new(on_deactivate),
            on_error: Mutex::new(on_error),
            on_shutdown: Mutex::new(on_shutdown),
            state_machine,
            _parameter_map,
        })
    }
    

    fn create_rcl_node_options(&self) -> Result<rcl_node_options_t, RclrsError> {
        // SAFETY: No preconditions for this function.
        let mut rcl_node_options = unsafe { rcl_node_get_default_options() };

        let cstring_args = self
            .arguments
            .iter()
            .map(|s| match CString::new(s.as_str()) {
                Ok(cstr) => Ok(cstr),
                Err(err) => Err(RclrsError::StringContainsNul { s: s.clone(), err }),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let cstring_arg_ptrs = cstring_args.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
        unsafe {
            // SAFETY: This function does not store the ephemeral cstring_args_ptrs
            // pointers. We are passing in a zero-initialized arguments struct as expected.
            rcl_parse_arguments(
                cstring_arg_ptrs.len() as i32,
                cstring_arg_ptrs.as_ptr(),
                rcutils_get_default_allocator(),
                &mut rcl_node_options.arguments,
            )
        }
        .ok()?;

        rcl_node_options.use_global_arguments = self.use_global_arguments;
        rcl_node_options.enable_rosout = self.enable_rosout;
        // SAFETY: No preconditions for this function.
        rcl_node_options.allocator = unsafe { rcutils_get_default_allocator() };

        Ok(rcl_node_options)
    }
}
