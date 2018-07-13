(require crypto crypto/all)
(crypto-factories libcrypto-factory)

(define k (generate-private-key 'eddsa '((curve ed25519))))
(define fmt 'rkt-private) ;; FAIL
;;(define fmt 'rkt-public) ;; FAIL
;;(define fmt 'PrivateKeyInfo) ;; FAIL
;;(define fmt 'SubjectPublicKeyInfo);; FAIL
(define kdata (pk-key->datum k fmt))
(define k2 (datum->pk-key kdata fmt decaf-factory))

(printf "k1 = ~s\n" (pk-key->datum k  'rkt-public))
(printf "k2 = ~s\n" (pk-key->datum k2 'rkt-public))

(define msg #"hello world")
(define sig (pk-sign k msg))
(printf "ok? = ~s\n" (pk-verify k2 msg sig))

(define sig2 (pk-sign k2 msg))
(printf "sig1 = ~s\n" sig)
(printf "sig2 = ~s\n" sig2)

