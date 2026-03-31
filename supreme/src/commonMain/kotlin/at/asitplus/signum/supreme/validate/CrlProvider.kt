package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.deltaCRLIndicator
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.pki.CertificateList
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.generalNames.GeneralNameOption
import at.asitplus.signum.indispensable.pki.pkiExtensions.CRLDistributionPointsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.IssuingDistributionPointExtension
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.io.buffered
import kotlinx.io.files.FileSystem
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readByteArray

/**
 * Fetches Certificate Revocation Lists
 */
interface CrlProvider {
    /**
     * Attempts to find a valid CRL for the given issuer.
     */
    suspend fun getCrl(targetCert: X509Certificate, issuerCert: X509Certificate): List<CertificateList>

    /**
     * Fetch CRLs from CRL Distribution Points (CDP extension).
     */
    suspend fun getCrlsFromDistributionPoints(cert: X509Certificate): List<CertificateList>

    /**
     * Fetch Delta CRLs associated with a specific Base CRL.
     */
    suspend fun getDeltaCrls(baseCrl: CertificateList, targetCert: X509Certificate): List<CertificateList>
}


@ExperimentalPkiApi
object SystemCrlCache {
    private val mutex = Mutex()
    private var _cache: List<CertificateList>? = null

    /**
     * Provides the cache. Throws if accessed before [initialize] is called.
     */
    val crls: List<CertificateList>
        get() = _cache ?: throw IllegalStateException("SystemCrlCache not initialized. Call initialize() first.")

    /**
     * Suspendable initializer. Safe to call multiple times; only the first succeeds.
     */
    suspend fun initialize(path: String, fileSystem: FileSystem = SystemFileSystem) {
        if (_cache != null) return
        mutex.withLock {
            if (_cache == null) {
                val provider = DirectoryCrlProvider.create(path, fileSystem)
                _cache = provider.crlCache
            }
        }
    }
}

/**
 * A provider that loads and caches all CRLs from a specific local directory.
 * * It scans the directory for files ending in ".crl" (or another specified extension),
 * parses them, and holds them in memory for lightning-fast lookups during validation.
 */
class DirectoryCrlProvider @OptIn(ExperimentalPkiApi::class) constructor(
    val crlCache: List<CertificateList> = SystemCrlCache.crls
) : CrlProvider {

    /**
     * Finds the CRL issued by the [issuerCert].
     */
    @OptIn(ExperimentalPkiApi::class)
    override suspend fun getCrl(targetCert: X509Certificate, issuerCert: X509Certificate): List<CertificateList> {
        val issuerName = issuerCert.tbsCertificate.subjectName

        return crlCache.filter { crl ->
                crl.tbsCertList.issuer.constrains(issuerName) == GeneralNameOption.ConstraintResult.MATCH
            }
    }

    companion object {
        suspend fun create(
            folderPath: String,
            fileSystem: FileSystem = SystemFileSystem
        ): DirectoryCrlProvider = withContext(Dispatchers.Default) {
            val cache = mutableListOf<CertificateList>()
            val rootPath = Path(folderPath)

            if (!fileSystem.exists(rootPath)) {
                return@withContext DirectoryCrlProvider(emptyList())
            }

            fileSystem.list(rootPath).forEach { filePath ->
                if (filePath.name.endsWith(".crl", ignoreCase = true)) {
                    runCatching {
                        val bytes = fileSystem.source(filePath).buffered().use {
                            it.readByteArray()
                        }

                        val src = Asn1Element.parse(bytes) as Asn1Sequence
                        val crl = CertificateList.decodeFromTlv(src)

                        cache.add(crl)
                    }.onFailure {
                        println("Failed to load CRL at ${filePath.name}: ${it.message}")
                    }
                }
            }
            DirectoryCrlProvider(cache)
        }
    }

    override suspend fun getCrlsFromDistributionPoints(
        cert: X509Certificate
    ): List<CertificateList> {
        val result = mutableListOf<CertificateList>()
        val cdpExt = cert.findExtension<CRLDistributionPointsExtension>() ?: return emptyList()

        for (dp in cdpExt.distributionPoints) {
            val dpName = dp.distributionPointName
            val currentCrlIssuers = dp.crlIssuer

            for (crl in crlCache) {
                val idp = crl.findExtension<IssuingDistributionPointExtension>()
                val idpName = idp?.distributionPointName

                if (!currentCrlIssuers.isNullOrEmpty()) {
                    val isAuthorized = currentCrlIssuers.any { it.name == crl.tbsCertList.issuer }

                    if (isAuthorized && idp?.indirectCRL == true) {
                        if (dpName != null && idpName != null) {
                            if (matchesDistributionPointNames(
                                    idpName = idpName,
                                    idpBase = crl.tbsCertList.issuer,
                                    cdpName = dpName,
                                    cdpBase = crl.tbsCertList.issuer
                                )
                            ) {
                                result.add(crl)
                            }
                        } else {
                            result.add(crl)
                        }
                    }
                    continue
                }

                if (crl.tbsCertList.issuer != cert.tbsCertificate.issuerName) continue

                if (dpName != null) {
                    if (idpName != null) {
                        if (matchesDistributionPointNames(
                                idpName = idpName,
                                idpBase = crl.tbsCertList.issuer,
                                cdpName = dpName,
                                cdpBase = cert.tbsCertificate.issuerName
                            )
                        ) {
                            result.add(crl)
                        }
                    } else {
                        result.add(crl)
                    }
                } else {
                    result.add(crl)
                }
            }
        }
        return result.distinct()
    }

    override suspend fun getDeltaCrls(
        baseCrl: CertificateList,
        targetCert: X509Certificate
    ): List<CertificateList> {
        val baseIssuer = baseCrl.tbsCertList.issuer
        val baseIdp = baseCrl.findExtension<IssuingDistributionPointExtension>()

        return crlCache.filter { crl ->
            // 1. Must have the same issuer as the base CRL
            if (crl.tbsCertList.issuer != baseIssuer) return@filter false

            // 2. Must be a Delta CRL (contains DeltaCRLIndicator extension)
            val isDelta = crl.tbsCertList.extensions?.any { it.oid == KnownOIDs.deltaCRLIndicator } == true
            if (!isDelta) return@filter false

            // 3. IssuingDistributionPoint must match exactly between Base and Delta CRL
            val deltaIdp = crl.findExtension<IssuingDistributionPointExtension>()
            deltaIdp == baseIdp
        }
    }
}