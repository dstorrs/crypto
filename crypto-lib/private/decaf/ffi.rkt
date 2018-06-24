;; Copyright 2018 Ryan Culpepper
;; 
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require ffi/unsafe
         ffi/unsafe/define)
(provide (protect-out (all-defined-out)))

(define libdecaf (ffi-lib "libdecaf" '(#f) #:fail (lambda () #f)))

(define-ffi-definer define-decaf libdecaf
  #:default-make-fail make-not-available)

(define ((K v) . as) v)

;; ============================================================
;; common

(define DECAF_WORD_BITS 64)   ;; 64 or 32
(define _decaf_word  _uint64) ;; or _uint32
(define _decaf_sword _int64)  ;; or _int32
(define _decaf_bool  _uint64) ;; or _uint32; either 0 or all ones (#xFF..FF)

(define _decaf_dword  _uint64)
(define _decaf_dsword _int64)

(define _decaf_error _int) ;; 0 = ok, -1 = failure

;; ============================================================
;; curve25519

;; The number of bits in a scalar.
(define DECAF_255_SCALAR_BITS 253)
(define DECAF_255_SCALAR_LIMBS (+ 1 (quotient 252 DECAF_WORD_BITS)))

;; Galois field element internal structure
(define-cstruct _gf_25519_s
  ([limb (_array _decaf_word (/ 320 DECAF_WORD_BITS))]))
(define _gf_25519 _gf_25519_s-pointer)

;; Number of bytes in a serialized point.
(define DECAF_255_SER_BYTES 32)

;; Number of bytes in an elligated point.  For now set the same as
;; SER_BYTES but could be different for other curves.
(define DECAF_255_HASH_BYTES 32)

;; Number of bytes in a serialized scalar.
(define DECAF_255_SCALAR_BYTES 32)

;; Number of bits in the "which" field of an elligator inverse
(define DECAF_255_INVERT_ELLIGATOR_WHICH_BITS 5)

;; The cofactor the curve would have, if we hadn't removed it
(define DECAF_255_REMOVED_COFACTOR 8)

;; X25519 encoding ratio.
(define DECAF_X25519_ENCODE_RATIO 4)

;; Number of bytes in an x25519 public key
(define DECAF_X25519_PUBLIC_BYTES 32)

;; Number of bytes in an x25519 private key
(define DECAF_X25519_PRIVATE_BYTES 32)

;; Representation of a point on the elliptic curve.
(define-cstruct _decaf_255_point_s
  ;;([x _gf_25519_s] [y _gf_25519_s] [z _gf_25519_s] [t _gf_25519_s])
  ([xyzt (_array _gf_25519_s 4)]))
(define _decaf_255_point _decaf_255_point_s-pointer)

(define (new-decaf_255_point)
  ;; Needs to be 32-byte aligned! Thus the hackery below:
  (define (round-up-to n by) (+ n (modulo (- n) by)))
  (define p0 (malloc (+ 32 (ctype-sizeof _decaf_255_point_s)) 'atomic-interior))
  (define p (cast (round-up-to (cast p0 _pointer _uintptr) 32) _uintptr _pointer))
  (cpointer-push-tag! p decaf_255_point_s-tag)
  p)

;; Representation of an element of the scalar field.
(define-cstruct _decaf_255_scalar_s
  ([limb (_array _decaf_word DECAF_255_SCALAR_LIMBS)]))
(define _decaf_255_scalar _decaf_255_scalar_s-pointer)

(define (new-decaf_255_scalar)
  (define p (malloc _decaf_255_scalar_s))
  (cpointer-push-tag! p decaf_255_scalar_s-tag)
  p)

;;(define-decaf decaf_255_scalar_one  _decaf_255_scalar #:fail (K #f))
;;(define-decaf decaf_255_scalar_zero _decaf_255_scalar #:fail (K #f))
;;(define-decaf decaf_255_point_identity _decaf_255_point #:fail (K #f))
(require (only-in '#%foreign ffi-obj))
(define decaf_255_point_base
  (cast (ffi-obj #"decaf_255_point_base" libdecaf) _pointer _decaf_255_point))
;; (define-decaf decaf_255_point_base     _decaf_255_point_s #:fail (K #f))

;; (define-cpointer-type _decaf_255_precomputed)
;; (define-decaf decaf_255_sizeof_precomputed_s  _size #:fail (lambda () 0))
;; (define-decaf decaf_255_alignof_precomputed_s _size #:fail (lambda () 0))
;; (define-decaf defac_255_precomputed_base _decaf_255_precomputed #:fail (K #f))

;; Read a scalar from wire format or from bytes.  Reduces mod scalar prime.
(define-decaf decaf_255_scalar_decode_long
  (_fun (out : _decaf_255_scalar) (ser : _bytes) (len : _size = (bytes-length ser))
        -> _void))

;; Serialize a scalar to wire format.
(define-decaf decaf_255_scalar_encode
  (_fun (out : _bytes = (make-bytes DECAF_255_SCALAR_BYTES))
        (s : _decaf_255_scalar)
        -> _void -> out))

(define-decaf decaf_255_scalar_eq
  (_fun _decaf_255_scalar _decaf_255_scalar -> _decaf_bool))

(define-decaf decaf_255_scalar_add
  (_fun (out : _decaf_255_scalar) _decaf_255_scalar _decaf_255_scalar -> _void))
(define-decaf decaf_255_scalar_sub
  (_fun (out : _decaf_255_scalar) _decaf_255_scalar _decaf_255_scalar -> _void))
(define-decaf decaf_255_scalar_mul
  (_fun (out : _decaf_255_scalar) _decaf_255_scalar _decaf_255_scalar -> _void))
(define-decaf decaf_255_scalar_halve
  (_fun (out : _decaf_255_scalar) _decaf_255_scalar -> _void))
(define-decaf decaf_255_scalar_invert
  (_fun (out : _decaf_255_scalar) _decaf_255_scalar -> _decaf_error))
(define-decaf decaf_255_scalar_set_unsigned
  (_fun (out : _decaf_255_scalar) _uint64 -> _void))

;; Encode a point as a sequence of bytes.
(define-decaf decaf_255_point_encode
  (_fun (out : _bytes = (make-bytes DECAF_255_SER_BYTES))
        (point : _decaf_255_point)
        -> _void -> out))

;; Decode a point from a sequence of bytes.
(define-decaf decaf_255_point_decode
  (_fun (out : _decaf_255_point)
        (ser : _pointer) ;; uint8_t[DECAF_255_SER_BYTES]
        (allow-identity? : _decaf_bool)
        -> _decaf_error))

(define-decaf decaf_255_point_eq
  (_fun _decaf_255_point _decaf_255_point -> _decaf_bool))

(define-decaf decaf_255_point_add
  (_fun (out : _decaf_255_point) _decaf_255_point _decaf_255_point -> _void))

(define-decaf decaf_255_point_double
  (_fun (out : _decaf_255_point) _decaf_255_point -> _void))

(define-decaf decaf_255_point_sub
  (_fun (out : _decaf_255_point) _decaf_255_point _decaf_255_point -> _void))

(define-decaf decaf_255_point_negate
  (_fun (out : _decaf_255_point) _decaf_255_point -> _void))

(define-decaf decaf_255_point_scalarmul
  (_fun (out : _decaf_255_point) _decaf_255_point _decaf_255_scalar -> _void))

(define-decaf decaf_255_direct_scalarmul
  (_fun (out : _bytes = (make-bytes DECAF_255_SER_BYTES))
        (base : _bytes)
        (scalar : _decaf_255_scalar)
        (allow-identity? : _decaf_bool)
        (short-circuit? : _decaf_bool)
        -> (s : _decaf_error) -> (and (zero? s) out)))

;; RFC 7748 Diffie-Hellman scalarmul, used to compute shared secrets.
;; This function uses a different (non-Decaf) encoding.
(define-decaf decaf_x25519
  (_fun (out : _bytes = (make-bytes DECAF_X25519_PUBLIC_BYTES))
        (base : _bytes) ;; DECAF_X25519_PUBLIC_BYTES
        (scalar : _bytes) ;; DECAF_X25519_PRIVATE_BYTES
        -> (s : _decaf_error)
        -> (and (zero? s) out)))

;; Multiply a point by DECAF_X25519_ENCODE_RATIO, then encode it like RFC 7748.
(define-decaf decaf_255_point_mul_by_ratio_and_encode_like_x25519
  (_fun (out : _bytes = (make-bytes DECAF_X25519_PUBLIC_BYTES))
        _decaf_255_point
        -> _void -> out))

;; The base point for X25519 Diffie-Hellman
(define-decaf decaf_x25519_base_point _pointer #:fail (K #f))
;; extern const uint8_t decaf_x25519_base_point[DECAF_X25519_PUBLIC_BYTES];

;; RFC 7748 Diffie-Hellman base point scalarmul.  This function uses a
;; different (non-Decaf) encoding.
(define-decaf decaf_x25519_derive_public_key
  (_fun (out : _bytes = (make-bytes DECAF_X25519_PUBLIC_BYTES))
        (scalar : _pointer) ;; DECAF_X25519_PRIVATE_BYTES
        -> _void -> out))

;; Multiply two base points by two scalars:
;;   scaled = scalar1*base1 + scalar2*base2.
(define-decaf decaf_255_point_double_scalarmul
  (_fun (out : _decaf_255_point)
        (base1 : _decaf_255_point) (scalar1 : _decaf_255_scalar)
        (base2 : _decaf_255_point) (scalar2 : _decaf_255_scalar)
        -> _void))

;; Multiply one base point by two scalars:
;;   a1 = scalar1 * base        a2 = scalar2 * base
(define-decaf decaf_255_point_dual_scalarmul
  (_fun (a1 : _decaf_255_point) (a2 : _decaf_255_point)
        (base1 : _decaf_255_point)
        (scalar1 : _decaf_255_point) (scalar : _decaf_255_point)
        -> _void))

;; Constant-time decision between two points.
;; If pick_b is zero, out = a; else out = b.
(define-decaf decaf_255_point_cond_sel
  (_fun (out : _decaf_255_point) _decaf_255_point _decaf_255_point _decaf_word
        -> _void))

;; Constant-time decision between two scalars.
;; If pick_b is zero, out = a; else out = b.
(define-decaf decaf_255_scalar_cond_sel
  (_fun (out : _decaf_255_scalar) _decaf_255_scalar _decaf_255_scalar _decaf_word
        -> _void))

(define-decaf decaf_255_point_valid
  (_fun _decaf_255_point -> _decaf_bool))

;; Almost-Elligator-like hash to curve.
(define-decaf decaf_255_point_from_hash_nonuniform
  (_fun _decaf_255_point
        _pointer ;; DECAF_255_HASH_BYTES
        -> _void))

;; Indifferentiable hash function encoding to curve.
(define-decaf decaf_255_point_from_hash_uniform
  (_fun _decaf_255_point
        _pointer ;; 2 * DECAF_255_HASH_BYTES
        -> _void))

;; Inverse of elligator-like hash to curve.
(define-decaf decaf_255_invert_elligator_nonuniform
  (_fun (out : _bytes = (make-bytes DECAF_255_HASH_BYTES))
        _decaf_255_point (which : _uint32)
        -> (s : _decaf_error) -> (and (zero? s) out)))

;; Inverse of elligator-like hash to curve.
(define-decaf decaf_255_invert_elligator_uniform
  (_fun (out : _bytes = (make-bytes (* 2 DECAF_255_HASH_BYTES)))
        _decaf_255_point (which : _uint32)
        -> (s : _decaf_error) -> (and (zero? s) out)))

;; Securely erase a scalar.
(define-decaf decaf_255_scalar_destroy
  (_fun _decaf_255_scalar -> _void))

;; Securely erase a point by overwriting it with zeros.
(define-decaf decaf_255_point_destroy
  (_fun _decaf_255_point -> _void))

;; ============================================================
;; ...
