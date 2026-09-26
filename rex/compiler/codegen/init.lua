local c_codegen = require("compiler.codegen.c_codegen")
local cmm_codegen = require("compiler.codegen.cmm_codegen")

return {
  generate = c_codegen.generate,
  -- Alternative backend that emits Cmm (C--) for `gmm`.  Selected with
  -- `--target cmm`; see `cmm_codegen.lua` for the gmm constraints it works
  -- around.
  generate_cmm = cmm_codegen.generate,
}
