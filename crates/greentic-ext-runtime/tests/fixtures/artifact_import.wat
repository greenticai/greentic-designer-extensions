(component
  (type $ty-greentic:extension-host/artifact@0.1.0 (;0;)
    (instance
      (type (;0;) (variant (case "unsupported") (case "tenant-required") (case "invalid-size") (case "invalid-input" string) (case "unsupported-media-type") (case "quota-exceeded") (case "unavailable")))
      (export (;1;) "artifact-error" (type (eq 0)))
      (type (;2;) (list u8))
      (type (;3;) (result string (error 1)))
      (type (;4;) (func (param "bytes" 2) (param "mime-type" string) (param "name" string) (result 3)))
      (export (;0;) "put" (func (type 4)))
    )
  )
  (import "greentic:extension-host/artifact@0.1.0" (instance $greentic:extension-host/artifact@0.1.0 (;0;) (type $ty-greentic:extension-host/artifact@0.1.0)))
  (core module $main (;0;)
    (type (;0;) (func (param i32 i32 i32 i32 i32 i32 i32)))
    (type (;1;) (func (param i32 i32 i32 i32) (result i32)))
    (type (;2;) (func (result i32)))
    (import "greentic:extension-host/artifact@0.1.0" "put" (func $put (;0;) (type 0)))
    (memory (;0;) 1)
    (export "memory" (memory 0))
    (export "cabi_realloc" (func 1))
    (export "touch" (func 2))
    (func (;1;) (type 1) (param i32 i32 i32 i32) (result i32)
      local.get 3
    )
    (func (;2;) (type 2) (result i32)
      i32.const 0
      i32.const 1
      i32.const 100
      i32.const 9
      i32.const 120
      i32.const 5
      i32.const 64
      call $put
      i32.const 64
      i32.load8_u
      i32.const 68
      i32.load8_u
      i32.const 8
      i32.shl
      i32.or
      i32.const 72
      i32.load
      i32.const 16
      i32.shl
      i32.or
    )
    (data (;0;) (i32.const 100) "image/png")
    (data (;1;) (i32.const 120) "a.png")
    (@producers
      (processed-by "wit-component" "0.255.0")
    )
  )
  (core module $wit-component-shim-module (;1;)
    (type (;0;) (func (param i32 i32 i32 i32 i32 i32 i32)))
    (table (;0;) 1 1 funcref)
    (export "0" (func 0))
    (export "$imports" (table 0))
    (func (;0;) (type 0) (param i32 i32 i32 i32 i32 i32 i32)
      local.get 0
      local.get 1
      local.get 2
      local.get 3
      local.get 4
      local.get 5
      local.get 6
      i32.const 0
      call_indirect (type 0)
    )
    (@producers
      (processed-by "wit-component" "0.255.0")
    )
  )
  (core module $wit-component-fixup (;2;)
    (type (;0;) (func (param i32 i32 i32 i32 i32 i32 i32)))
    (import "" "0" (func (;0;) (type 0)))
    (import "" "$imports" (table (;0;) 1 1 funcref))
    (elem (;0;) (i32.const 0) func 0)
    (@producers
      (processed-by "wit-component" "0.255.0")
    )
  )
  (core instance $wit-component-shim-instance (;0;) (instantiate $wit-component-shim-module))
  (alias core export $wit-component-shim-instance "0" (core func $indirect-greentic:extension-host/artifact@0.1.0-put (;0;)))
  (core instance $greentic:extension-host/artifact@0.1.0 (;1;)
    (export "put" (func $indirect-greentic:extension-host/artifact@0.1.0-put))
  )
  (core instance $main (;2;) (instantiate $main
      (with "greentic:extension-host/artifact@0.1.0" (instance $greentic:extension-host/artifact@0.1.0))
    )
  )
  (alias core export $main "memory" (core memory $memory (;0;)))
  (alias core export $wit-component-shim-instance "$imports" (core table $"shim table" (;0;)))
  (alias export $greentic:extension-host/artifact@0.1.0 "put" (func $put (;0;)))
  (alias core export $main "cabi_realloc" (core func $realloc (;1;)))
  (core func $"#core-func2 indirect-greentic:extension-host/artifact@0.1.0-put" (@name "indirect-greentic:extension-host/artifact@0.1.0-put") (;2;) (canon lower (func $put) (memory $memory) (realloc $realloc) string-encoding=utf8))
  (core instance $fixup-args (;3;)
    (export "$imports" (table $"shim table"))
    (export "0" (func $"#core-func2 indirect-greentic:extension-host/artifact@0.1.0-put"))
  )
  (core instance $fixup (;4;) (instantiate $wit-component-fixup
      (with "" (instance $fixup-args))
    )
  )
  (type (;1;) (func (result u32)))
  (alias core export $main "touch" (core func $touch (;3;)))
  (func $touch (;1;) (type 1) (canon lift (core func $touch)))
  (export $"#func2 touch" (@name "touch") (;2;) "touch" (func $touch))
  (@producers
    (processed-by "wit-component" "0.255.0")
  )
)
