;; Copyright 2014 Ryan Culpepper
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
(provide (all-defined-out))
#;
(provide unsigned->base256
         signed->base256
         base256->unsigned
         base256->signed

         wrap

         wrap-bit-string
         bit-string->der
         decode-bit-string

         ia5string?
         wrap-ia5string
         ia5string->der
         decode-ia5string

         wrap-integer
         integer->der
         decode-integer

         wrap-null
         null->der

         wrap-object-identifier
         object-identifier->der
         decode-object-identifier

         wrap-octet-string
         octet-string->der

         printable-string?
         wrap-printable-string
         printable-string->der
         decode-printable-string

         wrap-sequence
         sequence->der

         wrap-set
         set->der

         unwrap-der
         read-der)

;; Reference: http://luca.ntop.org/Teaching/Appunti/asn1.html

(define type-tag-classes
  '(universal application private context-specific))

(define type-tags
  '([INTEGER            2   primitive]
    [BIT-STRING         3   primitive]
    [OCTET-STRING       4   primitive]
    [NULL               5   primitive]
    [OBJECT-IDENTIFIER  6   primitive]
    [SEQUENCE          16   constructed]
    [SET               17   constructed]
    [PrintableString   19   primitive]
    [T61String         20   primitive]
    [IA5String         22   primitive]
    [UTCTime           23   primitive]))

;; A Tag is (list TagClass TagNumber)
;; A CTag is (cons (U 'primitive 'constructed) Tag)

(define (type->tag-entry type)
  (for/or ([entry (in-list type-tags)])
    (and (eq? type (car entry)) entry)))

(define (tagn->tag-entry tagn)
  (for/or ([entry (in-list type-tags)])
    (and (equal? tagn (cadr entry)) entry)))

(define (tag-entry-type te) (car te))
(define (tag-entry-tagn te) (cadr te))
(define (tag-entry-p/c te) (caddr te))
(define (tag-entry-tag te) (list 'universal (tag-entry-tagn te)))

;; ----

;; BER (restricted to definite-length) encoding has 3:
;; - identifier - class, tag, primitive vs constructed
;; - length - number of contents octets
;; - content

;; == Primitive, definite-length ==
;; Tags:
;;   for low tag number (0-30):
;;     bits 8,7 are class, bit 6 is 0, bits 5-1 are tag number
;;     classes: universal (0,0); application (0,1); context-sensitive (1,0); private (1,1)
;;   for high tag number: ... (don't need yet)
;; Length octets:
;;   short (0 to 127): bit 8 is 0, bits 7-1 are value
;;   long (128 to 2^1008-1):
;;     first octet: bit 8 is 1, bits 7-1 give number of following length octets
;;     rest of octets are base-256 number

;; == Constructed, definite-length ==
;; Tags: same as primitive, except bit 6 is 1 to indicate constructed
;; Length octets: same as primitive

;; == Alternative tagging ==
;; class is context-sensitive unless overridden in defn
;; Implicit:
;;   change tag of component
;;   inherit prim/cons from underlying type
;; Explicit:
;;   adds outer tag
;;   always constructed

;; ----------------------------------------

;; wrap : symbol bytes [Tag] -> bytes
(define (wrap type c [alt-tag #f])
  (define tag-entry
    (or (type->tag-entry type)
        (error 'wrap "unknown type: ~e" type)))
  (bytes-append (tag-entry->tag-bytes tag-entry alt-tag) (length-code c) c))

;; tag-entry->tag-bytes : TagEntry [Tag] -> bytes
(define (tag-entry->tag-bytes te [alt-tag #f])
  (if alt-tag
      (get-tag-bytes (car alt-tag) (tag-entry-p/c te) (cadr alt-tag))
      (get-tag-bytes 'universal (tag-entry-p/c te) (tag-entry-tagn te))))

;; get-tag-bytes : ... -> bytes
(define (get-tag-bytes class p/c tagn)
  (bytes
   (+ (case class
        [(universal)        0]
        [(application)      #b01000000]
        [(context-specific) #b10000000]
        [(private)          #b11000000])
      (case p/c
        [(primitive)   0]
        [(constructed) #b00100000])
      tagn)))

;; length-code : (U nat bytes) -> bytes
(define (length-code n)
  (if (bytes? n)
      (length-code (bytes-length n))
      (cond [(<= 0 n 127)
             (bytes n)]
            [else
             (let ([nc (unsigned->base256 n)])
               (unless (< 128 (bytes-length nc))
                 (error 'length-code "length too long: ~e" n))
               (bytes-append
                (bytes (bitwise-ior 128 (bytes-length nc)))
                nc))])))

(define (unsigned->base256 n)
  (unless (exact-nonnegative-integer? n)
    (raise-argument-error 'unsigned->base256 "exact-nonnegative-integer?" n))
  (nonnegative-integer->base256 n #f))

(define (signed->base256 n)
  (unless (exact-integer? n)
    (raise-argument-error 'signed->base256 "exact-integer?" n))
  (if (negative? n)
      (negative-integer->base256 n)
      (nonnegative-integer->base256 n #t)))

(define (nonnegative-integer->base256 n as-signed?)
  (if (zero? n)
      #"0"
      (apply bytes
             (let loop ([n n] [acc null])
               (if (zero? n)
                   (if (and as-signed? (> (car acc) 127))
                       (cons 0 acc)
                       acc)
                   (let ([r (bitwise-bit-field n 0 8)]
                         [q (arithmetic-shift n -8)])
                     (loop q (cons r acc))))))))

(define (negative-integer->base256 n)
  (apply bytes
         (let loop ([n n] [acc null])
           (cond [(<= -128 n -1)
                  (cons (+ 256 n) acc)]
                 [else
                  (let* ([b (bitwise-bit-field n 0 8)]
                         [q (arithmetic-shift n -8)])
                    (loop q (cons b acc)))]))))

(define (base256->unsigned bs)
  (for/fold ([n 0]) ([b (in-bytes bs)])
    (+ (arithmetic-shift n 8) b)))

(define (base256->signed bs)
  (if (and (positive? (bytes-length bs)) (> (bytes-ref bs 0) 127))
      (- (base256->unsigned bs)
         (arithmetic-shift 1 (* 8 (bytes-length bs))))
      (base256->unsigned bs)))

;; ============================================================

;; Conventions:

;; wrap-<type> : bytes -> bytes
;; Accepts contents as given, appends tag and length

;; <type>->der : ??? -> bytes

;; === Bit string ===

;; wrap-bit-string : bytes [Tag] -> bytes
(define (wrap-bit-string c [alt-tag #f])
  (wrap 'BIT-STRING c alt-tag))

;; bit-string->der : bytes [Tag] -> bytes
;; Given bytes and number of trailing bits not significant (0-7)
(define (bit-string->der bits [alt-tag #f])
  (define trailing-unused 0) ;; FIXME: accept trailing unused ...
  (wrap-bit-string (bytes-append (bytes trailing-unused) bits) alt-tag))

(define (encode-bit-string bits trailing-unused)
  ;; FIXME: make sure trailing unused bits are 0
  (bytes-append (bytes trailing-unused) bits))

;; decode-bit-string : bytes -> bytes
;; Given encoded content, returns raw bit string
;; FIXME: trailing-unused bits must be zero!
(define (decode-bit-string c)
  (when (zero? (bytes-length c))
    (error 'decode-bit-string "ill-formed bit-string encoding: empty"))
  (let ([trailing-unused (bytes-ref c 0)])
    (unless (zero? trailing-unused)
      (error 'decode-bit-string "partial-octet bit strings not supported"))
    (subbytes c 1 (bytes-length c))))

;; === IA5String (ie, ASCII string) ===

;; ia5string? : any -> boolean
(define (ia5string? s)
  (and (string? s)
       (for/and ([c (in-string s)])
         (< (char->integer c) 256))))

;; wrap-ia5string : bytes [Tag] -> bytes
(define (wrap-ia5string c [alt-tag #f])
  (wrap 'IA5String c alt-tag))

;; ia5string->der : ia5string [Tag] -> bytes
(define (ia5string->der s [alt-tag #f])
  (unless (ia5string? s)
    (raise-argument-error 'ia5string->der "ia5string?" s))
  (wrap-ia5string (string->bytes/latin-1 s) alt-tag))

;; decode-ia5string : bytes -> string
(define (decode-ia5string bs)
  (define s (bytes->string/latin-1 bs))
  (unless (ia5string? s)
    (error 'decode-ia5string "not an ia5string: ~e" s))
  s)

;; === Integer ===

;; base-256, two's-complement (!!), most significant octet first
;; zero encoded as 1 octet

;; wrap-integer : bytes [Tag] -> bytes
(define (wrap-integer c [alt-tag #f])
  (wrap 'INTEGER c alt-tag))

;; integer->der : exact-integer [Tag] -> bytes
(define (integer->der n [alt-tag #f])
  (wrap-integer (signed->base256 n) alt-tag))

;; decode-integer : bytes -> integer
;; Given encoded integer, returns raw integer
(define (decode-integer bs)
  (base256->signed bs))

;; === Null ===

;; wrap-null : bytes [Tag] -> bytes
(define (wrap-null _ignored [alt-tag #f])
  (wrap 'NULL #"" alt-tag))

;; null->der : [Tag] -> bytes
(define (null->der _ignored [alt-tag #f])
  (wrap-null #"" alt-tag))

;; === Object Identifier ==

;; If OID = c1, c2, ... cN, then
;; first octet is 40*c1 + c2
;; following octets are c3, ... cN encoded as follows:
;;   base-128, most-significant first, high bit set on all but last octet of encoding

;; wrap-object-identifier : bytes [Tag] -> bytes
(define (wrap-object-identifier c [alt-tag #f])
  (wrap 'OBJECT-IDENTIFIER c alt-tag))

;; object-identifier->der : (listof (U nat (list symbol nat))) [Tag] -> bytes
(define (object-identifier->der cs [alt-tag #f])
  (wrap-object-identifier (encode-object-identifier cs) alt-tag))

(define (encode-object-identifier cs)
  (let ([cs (for/list ([c (in-list cs)])
              (if (list? c) (cadr c) c))])
    (let ([c1 (car cs)]
          [c2 (cadr cs)]
          [cs* (cddr cs)])
      (apply bytes-append
             (bytes (+ (* 40 c1) c2))
             (map encode-oid-component cs*)))))

(define (encode-oid-component c)
  (define (loop c acc)
    (if (zero? c)
        acc
        (let-values ([(q r) (quotient/remainder c 128)])
          (loop q (cons (bitwise-ior 128 r) acc)))))
  (apply bytes
         (let-values ([(q r) (quotient/remainder c 128)])
           (loop q (list r)))))

(define (decode-object-identifier bs)
  (when (zero? (bytes-length bs))
    (error 'decode-object-identifier "empty" bs))
  (define in (open-input-bytes bs))
  (define b1 (read-byte in))
  (list* (quotient b1 40) (remainder b1 40)
         (let loop ()
           (if (eof-object? (peek-byte in))
               null
               (let ([c (decode-oid-component in)])
                 (cons c (loop)))))))

(define (decode-oid-component in)
  (let loop ([c 0])
    (let ([next (read-byte in)])
      (cond [(eof-object? next)
             (error 'decode-object-identifier "incomplete component")]
            [(< next 128)
             (+ next (arithmetic-shift c 7))]
            [else
             (loop (+ (- next 128) (arithmetic-shift c 7)))]))))

;; === Octet String ===

;; wrap-octet-string : bytes [Tag] -> bytes
(define (wrap-octet-string c [alt-tag #f])
  (wrap 'OCTET-STRING c alt-tag))

;; octet-string->der : bytes [Tag] -> bytes
(define (octet-string->der bs [alt-tag #f])
  (wrap-octet-string bs alt-tag))

;; === Printable string ===

(define (printable-string? s)
  (and (string? s) (regexp-match? #rx"^[-a-zA-Z0-9 '()+,./:=?]*$" s)))

;; wrap-printable-string : bytes [Tag] -> bytes
(define (wrap-printable-string c [alt-tag #f])
  (wrap 'PrintableString c alt-tag))

;; printable-string->der : printable-string [Tag] -> bytes
(define (printable-string->der s [alt-tag #f])
  (unless (printable-string? s)
    (raise-argument-error 'printable-string->der "printable-string?"))
  (wrap-printable-string (string->bytes/latin-1 s) alt-tag))

;; decode-printable-string : bytes -> printable-string
(define (decode-printable-string bs)
  (let ([s (bytes->string/latin-1 bs)])
    (if (printable-string? s)
        s
        (error 'decode-printable-string "not a printable string: ~e" s))))

;; Not needed yet.

;; === Sequence ===

;; wrap-sequence : bytes [Tag] -> bytes
(define (wrap-sequence c [alt-tag #f])
  (wrap 'SEQUENCE c alt-tag))

;; sequence->der : (listof bytes) [Tag] -> bytes
;; Argument is a list of DER-encoded values.
;; Assumes DEFAULT and OPTIONAL parts have already been stripped from list.
(define (sequence->der lst [alt-tag #f])
  (wrap-sequence (encode-sequence-value lst) alt-tag))

(define (encode-sequence-value lst)
  (apply bytes-append lst))

;; ===  Set ===

;; wrap-set : bytes [Tag] -> bytes
(define (wrap-set c [alt-tag #f])
  (wrap 'SET c alt-tag))

;; set->der : (listof bytes) [Tag] -> bytes
;; Argument is a list of DER-encoded values
(define (set->der lst [alt-tag #f])
  (wrap-set (encode-set-value lst) alt-tag))

(define (encode-set-value lst)
  (apply bytes-append (sort lst bytes<?)))

;; === T61String ===

;; Not needed yet.

;; === UTCTime ===

;; Not needed yet.


;; ----

;; ASN1 decoder is one of
;; - 'decode -- decode known types
;; - 'stop   -- leave encoded (asn1-encoded struct)
;; - something like an ASN1-Type with other decoders at leaves???

;; Control decoder by mapping of names (type names and element names?)
;; to decoder-control-function.

;; A DecoderControlFun is one of
;; - 'decode
;; - 'stop
;; - ((U Asn1-Type Asn1-Element-Type) Asn1-Tag Bytes -> Any)



;; TODO:
;; decompose-der : bytes -> (values Asn1-Tag Bytes)

;; ----

;; FIXME: add checking for premature EOF, etc

;; DER-Frame is (der-frame TagClass P/C TagNum bytes)
(struct der-frame (tagclass p/c tagn content) #:transparent)

;; unwrap-der : bytes -> DER-Frame
(define (unwrap-der der)
  (define in (open-input-bytes der))
  (begin0 (read-der in)
    (unless (eof-object? (peek-char in))
      (error 'unwrap-der "bytes left over"))))

;; unwrap-ders : bytes -> (listof DER-Frame)
(define (unwrap-ders der)
  (read-ders (open-input-bytes der)))

;; read-der : input-port -> DER-Frame
(define (read-der in)
  (let* ([tag (read-tag in)]
         [len (read-length-code in)]
         [c (read-bytes len in)])
    (der-frame (car tag) (cadr tag) (caddr tag) c)))

;; read-der : input-port -> (listof DER-Frame)
(define (read-ders in)
  (if (eof-object? (peek-char in))
      null
      (cons (read-der in) (read-ders in))))

;; read-tag : input-port -> (list TagClass P/C TagNum)
(define (read-tag in)
  (let* ([tag (read-byte in)]
         [c? (bitwise-bit-set? tag (sub1 6))]
         [tagclass (bitwise-bit-field tag 6 8)]
         [tagnum (bitwise-and tag 31)])
    (unless (<= 0 tagnum 30)
      (error 'unwrap-der "only low tags implemented"))
    (list (case tagclass
            [(#b00) 'universal]
            [(#b01) 'application]
            [(#b10) 'context-specific]
            [(#b11) 'private])
          (if c? 'constructed 'primitive)
          tagnum)))

;; read-length-code : input-port -> nat
(define (read-length-code in)
  (let ([l (read-byte in)])
    (cond [(<= 0 l 127)
           l]
          [else
           (let* ([ll (- l 128)]
                  [lbs (read-bytes ll in)])
             (base256->unsigned lbs))])))