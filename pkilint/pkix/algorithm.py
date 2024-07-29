import binascii

from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc5280, rfc5480, rfc8410

from pkilint import validation, document

SIGNATURE_ALGORITHM_IDENTIFIER_MAPPINGS = {
    **{o: document.ValueDecoder.VALUE_NODE_ABSENT for o in (
        rfc8410.id_Ed448,
        rfc8410.id_Ed25519,
        rfc8410.id_X448,
        rfc8410.id_X25519,
        rfc5480.id_dsa_with_sha1,
        rfc5480.id_dsa_with_sha224,
        rfc5480.id_dsa_with_sha256,
        rfc5480.ecdsa_with_SHA1,
        rfc5480.ecdsa_with_SHA224,
        rfc5480.ecdsa_with_SHA256,
        rfc5480.ecdsa_with_SHA384,
        rfc5480.ecdsa_with_SHA512,
    )},
    **{o: univ.Null() for o in (
        rfc5480.md2WithRSAEncryption,
        rfc5480.md5WithRSAEncryption,
        rfc5480.sha1WithRSAEncryption,
        rfc4055.sha224WithRSAEncryption,
        rfc4055.sha256WithRSAEncryption,
        rfc4055.sha384WithRSAEncryption,
        rfc4055.sha512WithRSAEncryption,
    )},
    rfc4055.id_RSASSA_PSS: rfc4055.RSASSA_PSS_params(),
}

ALLOWED_SIGNATURE_ALGORITHM_ENCODINGS = set(
    map(
        binascii.a2b_hex, [
            # RSASSA‐PKCS1‐v1_5 with SHA‐256
            '300d06092a864886f70d01010b0500',
            # RSASSA‐PKCS1‐v1_5 with SHA‐384
            '300d06092a864886f70d01010c0500',
            # RSASSA‐PKCS1‐v1_5 with SHA‐512
            '300d06092a864886f70d01010d0500',
            # RSASSA‐PSS with SHA‐256, MGF‐1 with SHA‐256, and a salt length of 32 bytes
            '304106092a864886f70d01010a3034a00f300d060960864801650'
            '30402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120',
            # RSASSA‐PSS with SHA‐384, MGF‐1 with SHA‐384, and a salt length of 48 bytes
            '304106092a864886f70d01010a3034a00f300d060960864801650'
            '30402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130',
            # RSASSA‐PSS with SHA‐512, MGF‐1 with SHA‐512, and a salt length of 64 bytes
            '304106092a864886f70d01010a3034a00f300d060960864801650'
            '30402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140',
            # ECDSA with SHA‐256
            '300a06082a8648ce3d040302',
            # ECDSA with SHA‐384
            '300a06082a8648ce3d040303',
            # Ed25519
            '300506032b6570',
            # Ed448
            '300506032b6571'
        ]
    )
)

# must be extended
not_allowed_signature_algorithm_encodings = {
    # src: https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/
    "300d06092a864886f70d0101050500" : "RSASSA-PKCS1-v1_5 with SHA-1",
    # ECDSA with SHA‐512, src: https://letsencrypt.org/documents/isrg-cp-v3.3/
    "300a06082a8648ce3d040304" : "ECDSA with SHA‐512"
}


class AlgorithmIdentifierDecodingValidator(validation.DecodingValidator):
    def __init__(self, *, decode_func, **kwargs):
        super().__init__(pdu_class=rfc5280.AlgorithmIdentifier,
                         decode_func=decode_func,
                         **kwargs
                         )


class AllowedSignatureAlgorithmEncodingValidator(validation.Validator):
    def __init__(self, *, validation, allowed_encodings, **kwargs):
        self._allowed_encodings = allowed_encodings

        super().__init__(
            validations=[validation],
            **kwargs
        )

    def validate(self, node):
        encoded = encode(node.pdu)
        if encoded not in self._allowed_encodings:
            encoded_str = binascii.hexlify(encoded).decode('us-ascii')
            try:
                # output for prohibited signature algorithm encoding
                signature_algorithms_str = not_allowed_signature_algorithm_encodings[str(encoded_str)]
            except:
                signature_algorithms_str = "unknown" 

            raise validation.ValidationFindingEncountered(
                self._validations[0],
                f'Prohibited encoding: {encoded_str} Signature algorithms: {signature_algorithms_str}'
            )
