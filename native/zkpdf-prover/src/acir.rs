//! Version-pinned ACVM execution without foreign calls, logging, or networking.

use crate::{Error, Result};
use acvm::acir::{
    circuit::Program,
    native_types::{WitnessMap, WitnessStack},
    FieldElement,
};
use acvm::pwg::{ACVMStatus, ACVM};
use acvm::AcirField;
use base64::{engine::general_purpose::STANDARD, Engine};
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use noirc_abi::{input_parser::Format, Abi};
use serde::Deserialize;

#[derive(Deserialize)]
struct Artifact {
    abi: Abi,
    bytecode: String,
}

pub struct Executed {
    pub bytecode: Vec<u8>,
    pub witness: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

/// Flatten public ABI parameters without performing witness execution.
pub fn public_inputs(artifact: &[u8], inputs: &serde_json::Value) -> Result<Vec<u8>> {
    let artifact: Artifact = serde_json::from_slice(artifact).map_err(|_| Error("acir_json"))?;
    let input = Format::Json
        .parse(&inputs.to_string(), &artifact.abi)
        .map_err(|_| Error("acir_input"))?;
    let witness = artifact
        .abi
        .encode(&input, None)
        .map_err(|_| Error("acir_input"))?;
    let mut index = 0;
    let mut output = Vec::new();
    for parameter in &artifact.abi.parameters {
        let end = index + parameter.typ.field_count();
        if parameter.is_public() {
            for i in index..end {
                output.extend(
                    witness
                        .get_index(i)
                        .ok_or(Error("acir_public_input"))?
                        .to_be_bytes(),
                );
            }
        }
        index = end;
    }
    Ok(output)
}

fn solve(
    program: &Program<FieldElement>,
    index: usize,
    initial: WitnessMap<FieldElement>,
    stack: &mut WitnessStack<FieldElement>,
    depth: usize,
) -> Result<WitnessMap<FieldElement>> {
    if depth > 64 {
        return Err(Error("acir_call_depth"));
    }
    let circuit = program.functions.get(index).ok_or(Error("acir_function"))?;
    let solver = Bn254BlackBoxSolver(true);
    let mut vm = ACVM::new(
        &solver,
        &circuit.opcodes,
        initial,
        &program.unconstrained_functions,
        &circuit.assert_messages,
    );
    loop {
        match vm.solve() {
            ACVMStatus::Solved => break,
            ACVMStatus::RequiresAcirCall(call) => {
                let called = call.id.as_usize();
                let solved = solve(program, called, call.initial_witness, stack, depth + 1)?;
                let returns = program.functions[called]
                    .return_values
                    .indices()
                    .iter()
                    .map(|i| solved.get_index(*i).copied().ok_or(Error("acir_return")))
                    .collect::<Result<Vec<_>>>()?;
                vm.resolve_pending_acir_call(returns);
            }
            // Frozen circuits need no foreign oracle. In particular, never
            // service print/debug calls or expose assertion payloads.
            ACVMStatus::RequiresForeignCall(_) => return Err(Error("acir_foreign_call")),
            _ => return Err(Error("witness_unsatisfied")),
        }
    }
    let witness = vm.finalize();
    stack.push(index as u32, witness.clone());
    Ok(witness)
}

/// Call only after the asset's complete JSON digest has been authenticated.
pub fn execute(artifact: &[u8], inputs: &serde_json::Value) -> Result<Executed> {
    let artifact: Artifact = serde_json::from_slice(artifact).map_err(|_| Error("acir_json"))?;
    let bytecode = STANDARD
        .decode(&artifact.bytecode)
        .map_err(|_| Error("acir_bytecode"))?;
    let program = Program::<FieldElement>::deserialize_program(&bytecode)
        .map_err(|_| Error("acir_program"))?;
    let input = Format::Json
        .parse(&inputs.to_string(), &artifact.abi)
        .map_err(|_| Error("acir_input"))?;
    let witness = artifact
        .abi
        .encode(&input, None)
        .map_err(|_| Error("acir_input"))?;
    let mut stack = WitnessStack::default();
    let solved = solve(&program, 0, witness, &mut stack, 0)?;
    let main = program.functions.first().ok_or(Error("acir_function"))?;
    let mut public_inputs = Vec::new();
    for index in main
        .public_parameters
        .indices()
        .iter()
        .chain(main.return_values.indices().iter())
    {
        let value = solved.get_index(*index).ok_or(Error("acir_public_input"))?;
        public_inputs.extend(value.to_be_bytes());
    }
    Ok(Executed {
        bytecode,
        witness: stack.serialize().map_err(|_| Error("witness_encoding"))?,
        public_inputs,
    })
}
