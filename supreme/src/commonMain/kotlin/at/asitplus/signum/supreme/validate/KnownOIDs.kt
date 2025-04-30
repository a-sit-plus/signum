//package at.asitplus.signum.supreme.validate
//
//enum class KnownOIDs(val oid: String) {
//    // Name attributes
//    CommonName("2.5.4.3"),
//    Surname("2.5.4.4"),
//    SerialNumber("2.5.4.5"),
//    CountryName("2.5.4.6"),
//    LocalityName("2.5.4.7"),
//    StateName("2.5.4.8"),
//    StreetAddress("2.5.4.9"),
//    OrgName("2.5.4.10"),
//    OrgUnitName("2.5.4.11"),
//    Title("2.5.4.12"),
//    GivenName("2.5.4.42"),
//    Initials("2.5.4.43"),
//    GenerationQualifier("2.5.4.44"),
//    DNQualifier("2.5.4.46"),
//
//    // Certificate extensions
//    SubjectDirectoryAttributes("2.5.29.9"),
//    SubjectKeyID("2.5.29.14"),
//    KeyUsage("2.5.29.15"),
//    PrivateKeyUsage("2.5.29.16"),
//    SubjectAlternativeName("2.5.29.17"),
//    IssuerAlternativeName("2.5.29.18"),
//    BasicConstraints("2.5.29.19"),
//    CRLNumber("2.5.29.20"),
//    ReasonCode("2.5.29.21"),
//    HoldInstructionCode("2.5.29.23"),
//    InvalidityDate("2.5.29.24"),
//    DeltaCRLIndicator("2.5.29.27"),
//    IssuingDistributionPoint("2.5.29.28"),
//    CertificateIssuer("2.5.29.29"),
//    NameConstraints("2.5.29.30"),
//    CRLDistributionPoints("2.5.29.31"),
//    CertificatePolicies("2.5.29.32"),
//    CE_CERT_POLICIES_ANY("2.5.29.32.0"),
//    PolicyMappings("2.5.29.33"),
//    AuthorityKeyID("2.5.29.35"),
//    PolicyConstraints("2.5.29.36"),
//    ExtendedKeyUsage("2.5.29.37"),
//    AnyExtendedKeyUsage("2.5.29.37.0"),
//    FreshestCRL("2.5.29.46"),
//    InhibitAnyPolicy("2.5.29.54");
//
//    companion object {
//        fun fromOid(oid: String): KnownOIDs? = entries.firstOrNull { it.oid == oid }
//    }
//}