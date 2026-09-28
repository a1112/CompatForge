use compatforge_debug::dap::{
    encode_message, sanitize_backend_message, sanitize_initialize_response, DapBinding, DapFrameDecoder, SafeDapRequest,
};
use serde_json::{json, Value};

fn request(command: &str, arguments: Value) -> Value {
    json!({"seq":1,"type":"request","command":command,"arguments":arguments})
}

#[test]
fn fragmented_frames_are_reassembled_without_losing_following_message() {
    let first = encode_message(&request("initialize", json!({}))).unwrap();
    let second = encode_message(&request("threads", json!({}))).unwrap();
    let mut decoder = DapFrameDecoder::default();
    let mut messages = Vec::new();
    for fragment in first.chunks(3) {
        messages.extend(decoder.push(fragment).unwrap());
    }
    assert_eq!(messages.len(), 1);
    messages.extend(decoder.push(&second).unwrap());
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[1]["command"], "threads");
}

#[test]
fn decoder_rejects_duplicate_oversized_and_malformed_length_without_allocating_body() {
    for header in [
        b"Content-Length: 1\r\nContent-Length: 1\r\n\r\n{}".as_slice(),
        b"Content-Length: 65537\r\n\r\n".as_slice(),
        b"Content-Length: -1\r\n\r\n".as_slice(),
        b"Content-Length: 1\n\n{}".as_slice(),
    ] {
        assert!(DapFrameDecoder::default().push(header).is_err());
    }
    assert!(encode_message(&json!({"long":"x".repeat(65_537)})).is_err());
}

#[test]
fn public_gateway_rejects_gdb_console_and_host_attachment_surfaces() {
    for command in [
        "evaluate",
        "completions",
        "readMemory",
        "writeMemory",
        "disassemble",
        "modules",
        "attach",
        "setExpression",
        "setVariable",
    ] {
        assert!(
            SafeDapRequest::parse(&request(command, json!({}))).is_err(),
            "{command}"
        );
    }
    for arguments in [
        json!({"program":"/tmp/other.exe"}),
        json!({"target":"remote 1.2.3.4:1234"}),
        json!({"pid":42}),
        json!({"env":{"LD_PRELOAD":"/tmp/evil.so"}}),
        json!({"cwd":"/tmp"}),
        json!({"__init":"shell touch /tmp/marker"}),
        json!({"preRunCommands":["shell id"]}),
    ] {
        assert!(SafeDapRequest::parse(&request("launch", arguments)).is_err());
    }
}

#[test]
fn launch_carries_only_a_managed_target_and_fixed_rewrite_will_supply_program() {
    let safe = SafeDapRequest::parse(&request(
        "launch",
        json!({"applicationId":"sample","generationId":"gen-job-1","launcherId":"main"}),
    ))
    .unwrap();
    assert!(matches!(safe, SafeDapRequest::Launch { .. }));
    assert!(SafeDapRequest::parse(&request(
        "launch",
        json!({"applicationId":"sample","generationId":"gen-other","launcherId":"main"})
    ))
    .is_err());
}

#[test]
fn breakpoints_are_bounded_plain_lines_without_conditions_or_log_expressions() {
    let safe = SafeDapRequest::parse(&request(
        "setBreakpoints",
        json!({"source":{"path":"/managed/src/probe.c","name":"probe.c"},"breakpoints":[{"line":7}]}),
    ))
    .unwrap();
    assert!(matches!(safe, SafeDapRequest::SetBreakpoints { .. }));
    for point in [
        json!({"line":0}),
        json!({"line":7,"condition":"system(1)"}),
        json!({"line":7,"logMessage":"{x}"}),
    ] {
        assert!(SafeDapRequest::parse(&request(
            "setBreakpoints",
            json!({"source":{"path":"/managed/src/probe.c"},"breakpoints":[point]})
        ))
        .is_err());
    }
    let huge = (0..129).map(|_| json!({"line":7})).collect::<Vec<_>>();
    assert!(SafeDapRequest::parse(&request(
        "setBreakpoints",
        json!({"source":{"path":"/managed/src/probe.c"},"breakpoints":huge})
    ))
    .is_err());
}

#[test]
fn variable_reads_and_frames_have_explicit_page_limits() {
    assert!(SafeDapRequest::parse(&request("variables", json!({"variablesReference":2,"count":65}))).is_err());
    assert!(SafeDapRequest::parse(&request("stackTrace", json!({"threadId":1,"levels":65}))).is_err());
    assert!(SafeDapRequest::parse(&request("variables", json!({"variablesReference":2,"count":64}))).is_ok());
    assert!(SafeDapRequest::parse(&request("stackTrace", json!({"threadId":1,"levels":64}))).is_ok());
}

#[test]
fn initialize_response_advertises_only_implemented_safe_features() {
    let upstream = json!({"seq":4,"request_seq":1,"type":"response","command":"initialize","success":true,"body":{"supportsEvaluateForHovers":true,"supportsReadMemoryRequest":true,"supportsWriteMemoryRequest":true,"supportsCompletionsRequest":true,"supportsConfigurationDoneRequest":true,"supportsTerminateRequest":true}});
    let safe = sanitize_initialize_response(upstream).unwrap();
    assert_eq!(safe["body"]["supportsConfigurationDoneRequest"], true);
    assert_eq!(safe["body"]["supportsTerminateRequest"], true);
    assert!(safe["body"].get("supportsDelayedStackTraceLoading").is_none());
    for prohibited in [
        "supportsEvaluateForHovers",
        "supportsReadMemoryRequest",
        "supportsWriteMemoryRequest",
        "supportsCompletionsRequest",
        "supportTerminateDebuggee",
        "supportsSingleThreadExecutionRequests",
    ] {
        assert!(safe["body"].get(prohibited).is_none(), "{prohibited}");
    }
    assert!(
        safe["body"].get("supportsCancelRequest").is_none(),
        "cancel is not an exposed request yet"
    );
}

#[test]
fn backend_cannot_request_ide_command_execution_or_invent_new_operations() {
    for message in [
        json!({"seq":3,"type":"request","command":"runInTerminal","arguments":{"args":["sh","-c","touch /tmp/marker"]}}),
        json!({"seq":3,"type":"request","command":"startDebugging","arguments":{}}),
        json!({"seq":3,"type":"event","event":"unknownExecutionEvent","body":{}}),
        json!({"seq":3,"type":"response","request_seq":1,"command":"evaluate","success":true}),
    ] {
        assert!(sanitize_backend_message(message).is_err());
    }
    assert!(
        sanitize_backend_message(json!({"seq":3,"type":"event","event":"stopped","body":{"reason":"breakpoint"}}))
            .is_ok()
    );
    assert!(sanitize_backend_message(
        json!({"seq":3,"type":"response","request_seq":1,"command":"threads","success":true,"body":{"threads":[]}})
    )
    .is_ok());
}

#[test]
fn ordinary_ide_initialize_and_detach_options_are_accepted_but_rewritten() {
    let init = request(
        "initialize",
        json!({"adapterID":"cppdbg","clientID":"vscode","linesStartAt1":true,"columnsStartAt1":true,"pathFormat":"path","supportsVariableType":true}),
    );
    assert!(matches!(
        SafeDapRequest::parse(&init).unwrap(),
        SafeDapRequest::Initialize { .. }
    ));
    assert!(matches!(
        SafeDapRequest::parse(&request(
            "disconnect",
            json!({"terminateDebuggee":false,"restart":false})
        ))
        .unwrap(),
        SafeDapRequest::Disconnect { .. }
    ));
    assert!(SafeDapRequest::parse(&request("disconnect", json!({"terminateDebuggee":true}))).is_err());
}

#[test]
fn gateway_binds_program_remote_target_and_source_paths_internally() {
    let target = compatforge_debug::DebugTarget {
        application_id: "sample".into(),
        generation_id: "gen-job-1".into(),
        launcher_id: "main".into(),
    };
    let binding = DapBinding::new(
        target.clone(),
        "/managed/bin/probe.exe",
        25000,
        [("/workspace/probe.c", "/managed/src/probe.c")],
    )
    .unwrap();
    let launch = SafeDapRequest::parse(&request(
        "launch",
        json!({"applicationId":"sample","generationId":"gen-job-1","launcherId":"main"}),
    ))
    .unwrap();
    let forwarded = binding.forward(&launch).unwrap();
    assert_eq!(forwarded["command"], "attach");
    assert_eq!(forwarded["arguments"]["program"], "/managed/bin/probe.exe");
    assert_eq!(forwarded["arguments"]["target"], "127.0.0.1:25000");
    let point = SafeDapRequest::parse(&request(
        "setBreakpoints",
        json!({"source":{"path":"/workspace/probe.c"},"breakpoints":[{"line":7}]}),
    ))
    .unwrap();
    assert_eq!(
        binding.forward(&point).unwrap()["arguments"]["source"]["path"],
        "/managed/src/probe.c"
    );
    let forged = SafeDapRequest::parse(&request(
        "setBreakpoints",
        json!({"source":{"path":"/tmp/other.c"},"breakpoints":[{"line":7}]}),
    ))
    .unwrap();
    assert!(binding.forward(&forged).is_err());
    let other = SafeDapRequest::parse(&request(
        "launch",
        json!({"applicationId":"other","generationId":"gen-job-1","launcherId":"main"}),
    ))
    .unwrap();
    assert!(binding.forward(&other).is_err());
}

#[test]
fn backend_sources_return_to_public_paths_and_ambiguous_reverse_maps_are_rejected() {
    let target = compatforge_debug::DebugTarget {
        application_id: "sample".into(),
        generation_id: "gen-job-1".into(),
        launcher_id: "main".into(),
    };
    assert!(DapBinding::new(
        target.clone(),
        "/managed/probe.exe",
        25000,
        [
            ("/workspace/a.c", "/managed/shared.c"),
            ("/workspace/b.c", "/managed/shared.c")
        ]
    )
    .is_err());
    let binding = DapBinding::new(
        target,
        "/managed/probe.exe",
        25000,
        [("/workspace/probe.c", "/managed/src/probe.c")],
    )
    .unwrap();
    let stack = json!({"seq":5,"type":"response","request_seq":3,"command":"stackTrace","success":true,
    "body":{"stackFrames":[
        {"id":1,"name":"inner","source":{"name":"probe.c","path":"/managed/src/probe.c"},"line":7},
        {"id":2,"name":"system","source":{"name":"hidden.c","path":"/private/hidden.c"},"line":1}
    ]}});
    let stack = binding.rewrite_backend_message(stack).unwrap();
    assert_eq!(stack["body"]["stackFrames"][0]["source"]["path"], "/workspace/probe.c");
    assert!(stack["body"]["stackFrames"][1].get("source").is_none());
    let breakpoint = json!({"seq":6,"type":"event","event":"breakpoint",
        "body":{"breakpoint":{"id":1,"verified":true,"source":{"path":"/managed/src/probe.c"}}}});
    let breakpoint = binding.rewrite_backend_message(breakpoint).unwrap();
    assert_eq!(breakpoint["body"]["breakpoint"]["source"]["path"], "/workspace/probe.c");
    let nested = json!({"seq":7,"type":"event","event":"output","body":{"source":{
        "path":"/private/root.c","sources":[{"path":"/managed/src/probe.c","sourceReference":99}]
    }}});
    let nested = binding.rewrite_backend_message(nested).unwrap();
    assert!(nested["body"]["source"].get("path").is_none());
    assert_eq!(nested["body"]["source"]["sources"][0]["path"], "/workspace/probe.c");
    assert!(nested["body"]["source"]["sources"][0].get("sourceReference").is_none());
    let attached = binding
        .rewrite_backend_message(json!({"seq":8,"type":"response","request_seq":2,
            "command":"attach","success":true,"body":{}}))
        .unwrap();
    assert_eq!(attached["command"], "launch");
}
