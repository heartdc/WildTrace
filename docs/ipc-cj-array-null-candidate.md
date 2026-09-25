# Candidate: IPC CJ array null validation

Status: `candidate`, `undetermined`; no OpenHarmony binary has been executed.

`CJByteArray` is a public C ABI value containing `int8_t *data` and `uint32_t len`. `FfiRpcMessageSequenceImplWriteByteArray` forwards it to `MessageSequenceImpl::CJ_WriteByteArray` without validating the pointer. The implementation checks capacity and then reads `value.data[i]` for every element. With `data == nullptr` and `len == 1`, the source-equivalent Clang ASan harness reports a zero-page SEGV at that read; `len == 0` and a valid one-byte array return normally.

Evidence is recorded in `.cache/cj-array-equivalent/result.json` and `cases/ipc_cj_array_null_validation/case.json`. This establishes a deterministic memory-safety failure in the copied conversion logic. It does not establish that a supported Cangjie caller can construct the malformed descriptor, that the API is reachable across a privilege boundary, or that the shipped OpenHarmony binary has the same code.

The analogous numeric array writers should be reviewed for the same missing `data == nullptr` check, but they remain separate candidates until their exact behavior is verified.
