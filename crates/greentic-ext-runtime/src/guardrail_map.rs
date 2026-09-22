//! Wire-serialisable verdict type for the `guardrail` extension interface.
//!
//! [`GuardrailVerdictWire`] is the JSON-round-trippable counterpart to the
//! bindgen-generated `Verdict` variant from
//! `greentic:extension-design/guardrail@0.3.0`. It lives here (not in
//! `types.rs`) to keep the guardrail concern isolated and to allow the
//! pure mapper tests to run without wasmtime.
//!
//! [`call_evaluate`] is the thin wasmtime bridge: given an open
//! `Store<HostState>` + `Instance`, it resolves the `evaluate` typed function,
//! deserialises `input_json` into the bindgen record, calls the component,
//! and maps the returned `Verdict` to [`GuardrailVerdictWire`].

use serde::{Deserialize, Serialize};

/// JSON-serialisable mirror of the WIT `verdict` variant.
///
/// Serialised with `"kind"` as the discriminant tag so consumers can
/// branch on it without knowing the internal enum layout.
///
/// ```json
/// {"kind":"accept"}
/// {"kind":"update","content":"…"}
/// {"kind":"deny","code":"permission_denied","message":"no","details":null}
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GuardrailVerdictWire {
    Accept,
    Update {
        content: String,
    },
    Deny {
        code: String,
        message: String,
        details: Option<String>,
    },
}

/// Resolve `evaluate` from an already-open store + instance and call it.
///
/// `func_idx` must be the export index returned by `get_export_index` for
/// the `evaluate` function inside the `greentic:extension-design/guardrail`
/// interface. `input_json` must be a JSON object matching [`InputDto`].
///
/// Returns the mapped [`GuardrailVerdictWire`] or a [`crate::RuntimeError`]
/// when the wasmtime typed-func call fails.
pub(crate) fn call_evaluate(
    store: &mut wasmtime::Store<crate::host_state::HostState>,
    instance: &wasmtime::component::Instance,
    func_idx: &wasmtime::component::ComponentExportIndex,
    input_json: &str,
) -> Result<GuardrailVerdictWire, crate::RuntimeError> {
    use crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::guardrail as gr;

    #[derive(Deserialize)]
    struct InputDto {
        direction: String,
        content: String,
        agent_id: String,
        session_id: String,
        tenant_id: String,
        env_id: String,
        context: Option<String>,
    }

    let dto: InputDto =
        serde_json::from_str(input_json).map_err(|e| crate::RuntimeError::Wasmtime(e.into()))?;

    let direction = parse_direction(&dto.direction)?;

    let input = gr::GuardrailInput {
        direction,
        content: dto.content,
        agent_id: dto.agent_id,
        session_id: dto.session_id,
        tenant_id: dto.tenant_id,
        env_id: dto.env_id,
        context: dto.context,
    };

    let func = instance
        .get_typed_func::<(gr::GuardrailInput,), (gr::Verdict,)>(&mut *store, func_idx)
        .map_err(|e| crate::RuntimeError::Wasmtime(e.into()))?;

    let (verdict,) = func
        .call(&mut *store, (input,))
        .map_err(|e| crate::RuntimeError::Wasmtime(e.into()))?;

    Ok(map_verdict(verdict))
}

/// Parse the `direction` field, refusing anything the WIT does not define.
///
/// Fail closed. Defaulting an unknown value to `inbound` meant a typo, or an
/// `outbound` field the caller forgot to set, silently evaluated the guardrail
/// against the wrong direction — and a guardrail that answers the wrong
/// question still answers `accept`.
fn parse_direction(
    raw: &str,
) -> Result<
    crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::guardrail::Direction,
    crate::RuntimeError,
>{
    use crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::guardrail as gr;
    match raw {
        "inbound" => Ok(gr::Direction::Inbound),
        "outbound" => Ok(gr::Direction::Outbound),
        other => Err(crate::RuntimeError::Wasmtime(anyhow::anyhow!(
            "guardrail direction must be \"inbound\" or \"outbound\", got {other:?}"
        ))),
    }
}

/// Map a bindgen [`Verdict`] to its wire-serialisable counterpart.
///
/// Pure function — no wasmtime I/O — so it can be unit-tested without
/// spinning up a component runtime.
fn map_verdict(
    verdict: crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::guardrail::Verdict,
) -> GuardrailVerdictWire {
    use crate::host_bindings::design_v03::exports::greentic::extension_design0_3_0::guardrail::Verdict;
    match verdict {
        Verdict::Accept => GuardrailVerdictWire::Accept,
        Verdict::Update(content) => GuardrailVerdictWire::Update { content },
        Verdict::Deny(info) => GuardrailVerdictWire::Deny {
            code: info.code,
            message: info.message,
            details: info.details,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_wire_round_trips() {
        let verdict = GuardrailVerdictWire::Update {
            content: "x".into(),
        };
        let serialised = serde_json::to_string(&verdict).unwrap();
        assert_eq!(serialised, r#"{"kind":"update","content":"x"}"#);
        let deserialised: GuardrailVerdictWire = serde_json::from_str(&serialised).unwrap();
        assert_eq!(deserialised, verdict);
    }

    #[test]
    fn deny_wire_round_trips() {
        let verdict = GuardrailVerdictWire::Deny {
            code: "permission_denied".into(),
            message: "no".into(),
            details: None,
        };
        let serialised = serde_json::to_string(&verdict).unwrap();
        let deserialised: GuardrailVerdictWire = serde_json::from_str(&serialised).unwrap();
        assert_eq!(deserialised, verdict);
    }

    #[test]
    fn accept_wire_round_trips() {
        let verdict = GuardrailVerdictWire::Accept;
        let serialised = serde_json::to_string(&verdict).unwrap();
        assert_eq!(serialised, r#"{"kind":"accept"}"#);
        let deserialised: GuardrailVerdictWire = serde_json::from_str(&serialised).unwrap();
        assert_eq!(deserialised, verdict);
    }
}
