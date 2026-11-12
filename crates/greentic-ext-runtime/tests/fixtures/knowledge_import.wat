;; A guest that imports greentic:extension-host/knowledge@0.1.0 and exports one
;; probe per operation. Each probe calls the import with fixed arguments and
;; returns a packed u32:
;;   bits 0-7   result tag (0 ok, 1 err)
;;   bits 8-15  on err: the knowledge-error case; on ok: a flag
;;              (create: `created`, read: `truncated`, remove: the bool)
;;   bits 16-31 on ok: a length (create: document-id, read: text, list: rows)
;; Arguments: knowledge-base "Handbook", name "note.md", text "hello",
;; document-id "doc-1".
(component
  (type $kty (instance
    (type (;0;) (variant (case "not-allowed") (case "not-found") (case "too-large")
      (case "invalid-media-type") (case "quota-exceeded") (case "unavailable")))
    (export (;1;) "knowledge-error" (type (eq 0)))
    (type (;2;) (record (field "document-id" string) (field "created" bool)))
    (export (;3;) "created" (type (eq 2)))
    (type (;4;) (record (field "name" string) (field "text" string) (field "truncated" bool)))
    (export (;5;) "document" (type (eq 4)))
    (type (;6;) (record (field "document-id" string) (field "name" string) (field "size-chars" u64)))
    (export (;7;) "document-info" (type (eq 6)))
    (type (;8;) (result 3 (error 1)))
    (type (;9;) (func (param "knowledge-base" string) (param "name" string) (param "text" string) (result 8)))
    (export "create" (func (type 9)))
    (type (;10;) (result 5 (error 1)))
    (type (;11;) (func (param "knowledge-base" string) (param "document-id" string) (result 10)))
    (export "read" (func (type 11)))
    (type (;12;) (list 7))
    (type (;13;) (result 12 (error 1)))
    (type (;14;) (func (param "knowledge-base" string) (result 13)))
    (export "list" (func (type 14)))
    (type (;15;) (result bool (error 1)))
    (type (;16;) (func (param "knowledge-base" string) (param "document-id" string) (result 15)))
    (export "remove" (func (type 16)))
  ))
  (import "greentic:extension-host/knowledge@0.1.0" (instance $k (type $kty)))

  ;; Memory and a bump allocator, instantiated first so the lowered imports
  ;; can name them.
  (core module $mem
    (memory (export "memory") 1)
    (global $next (mut i32) (i32.const 1024))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $p i32)
      (local.set $p
        (i32.and
          (i32.add (global.get $next) (i32.sub (local.get 2) (i32.const 1)))
          (i32.xor (i32.sub (local.get 2) (i32.const 1)) (i32.const -1))))
      (global.set $next (i32.add (local.get $p) (local.get 3)))
      (local.get $p)))
  (core instance $m (instantiate $mem))
  (alias core export $m "memory" (core memory $memory))
  (alias core export $m "realloc" (core func $realloc))

  (alias export $k "create" (func $create))
  (alias export $k "read" (func $read))
  (alias export $k "list" (func $list))
  (alias export $k "remove" (func $remove))
  (core func $create-l (canon lower (func $create) (memory $memory) (realloc $realloc) string-encoding=utf8))
  (core func $read-l (canon lower (func $read) (memory $memory) (realloc $realloc) string-encoding=utf8))
  (core func $list-l (canon lower (func $list) (memory $memory) (realloc $realloc) string-encoding=utf8))
  (core func $remove-l (canon lower (func $remove) (memory $memory) (realloc $realloc) string-encoding=utf8))
  (core instance $kc
    (export "create" (func $create-l))
    (export "read" (func $read-l))
    (export "list" (func $list-l))
    (export "remove" (func $remove-l)))

  (core module $main
    (import "m" "memory" (memory 1))
    (import "k" "create" (func $create (param i32 i32 i32 i32 i32 i32 i32)))
    (import "k" "read" (func $read (param i32 i32 i32 i32 i32)))
    (import "k" "list" (func $list (param i32 i32 i32)))
    (import "k" "remove" (func $remove (param i32 i32 i32 i32 i32)))
    (data (i32.const 100) "Handbook")
    (data (i32.const 120) "note.md")
    (data (i32.const 140) "hello")
    (data (i32.const 160) "doc-1")
    ;; err: tag | case<<8 (case at retptr+4 for 4-aligned payloads)
    (func $err4 (result i32)
      (i32.or (i32.load8_u (i32.const 64)) (i32.shl (i32.load8_u (i32.const 68)) (i32.const 8))))
    (func (export "call-create") (result i32)
      (call $create (i32.const 100) (i32.const 8) (i32.const 120) (i32.const 7)
        (i32.const 140) (i32.const 5) (i32.const 64))
      (if (result i32) (i32.load8_u (i32.const 64))
        (then (call $err4))
        ;; created { document-id: (ptr@68, len@72), created@76 }
        (else (i32.or (i32.shl (i32.load8_u (i32.const 76)) (i32.const 8))
                      (i32.shl (i32.load (i32.const 72)) (i32.const 16))))))
    (func (export "call-read") (result i32)
      (call $read (i32.const 100) (i32.const 8) (i32.const 160) (i32.const 5) (i32.const 64))
      (if (result i32) (i32.load8_u (i32.const 64))
        (then (call $err4))
        ;; document { name: (68, 72), text: (76, 80), truncated@84 }
        (else (i32.or (i32.shl (i32.load8_u (i32.const 84)) (i32.const 8))
                      (i32.shl (i32.load (i32.const 80)) (i32.const 16))))))
    (func (export "call-list") (result i32)
      (call $list (i32.const 100) (i32.const 8) (i32.const 64))
      (if (result i32) (i32.load8_u (i32.const 64))
        (then (call $err4))
        ;; list<document-info>: (ptr@68, len@72)
        (else (i32.shl (i32.load (i32.const 72)) (i32.const 16)))))
    (func (export "call-remove") (result i32)
      (call $remove (i32.const 100) (i32.const 8) (i32.const 160) (i32.const 5) (i32.const 64))
      ;; result<bool, knowledge-error>: payload is 1-aligned, at retptr+1
      (i32.or (i32.load8_u (i32.const 64)) (i32.shl (i32.load8_u (i32.const 65)) (i32.const 8)))))
  (core instance $main-i (instantiate $main
    (with "m" (instance $m))
    (with "k" (instance $kc))))

  (func (export "call-create") (result u32) (canon lift (core func $main-i "call-create")))
  (func (export "call-read") (result u32) (canon lift (core func $main-i "call-read")))
  (func (export "call-list") (result u32) (canon lift (core func $main-i "call-list")))
  (func (export "call-remove") (result u32) (canon lift (core func $main-i "call-remove")))
)
