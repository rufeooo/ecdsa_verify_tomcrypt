openssl ecparam -genkey -name prime256v1 -out ecdsa-p256-private.pem
openssl ec -in ecdsa-p256-private.pem -pubout -out ecdsa-p256-public.pem
openssl dgst -sign ecdsa-p256-private.pem message > message_signature
openssl dgst -verify ecdsa-p256-public.pem -signature message_signature message
