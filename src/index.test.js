const { webcrypto } = require("node:crypto");
const pki = require("pkijs");
const asn1 = require("asn1js");

const crypto = new pki.CryptoEngine({ crypto: webcrypto });
const issuerName = "Issuer";
const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
const data = new TextEncoder().encode("Data");

const leafFirst = generateSignedTestData({ isLeafCertificateFirst: true });
const leafNotFirst = generateSignedTestData({ isLeafCertificateFirst: false });

test("leaf certificate first, not using Buffer", async () => {
  const info = await leafFirst;
  const result = await verifySignedData(info.toSchema().toBER());
  expect(result).toBe(true);
});

test("leaf certificate not first, not using Buffer", async () => {
  const info = await leafNotFirst;
  const result = await verifySignedData(info.toSchema().toBER());
  expect(result).toBe(true);
});

test("leaf certificate first, using Buffer", async () => {
  const info = await leafFirst;
  const buffer = Buffer.from(info.toSchema().toBER());
  const result = await verifySignedData(buffer);
  expect(result).toBe(true);
});

test("leaf certificate not first, using Buffer", async () => {
  const info = await leafNotFirst;
  const buffer = Buffer.from(info.toSchema().toBER());
  const result = await verifySignedData(buffer);
  expect(result).toBe(true);
});

async function generateSignedTestData(options) {
  const issuer = await generateKeyPair();
  const leaf = { ...(await generateKeyPair()), name: "Leaf" };

  const issuerCertificate = await issueCertificate(issuer, 1);
  const leafCertificate = await issueCertificate(issuer, 2, leaf);

  return await signMessage(
    data,
    leafCertificate,
    options.isLeafCertificateFirst
      ? [leafCertificate, issuerCertificate]
      : [issuerCertificate, leafCertificate],
    leaf.privateKey,
  );
}

async function verifySignedData(ber) {
  const schema = pki.ContentInfo.fromBER(ber).content;
  return await new pki.SignedData({ schema }).verify(
    { signer: 0, data },
    crypto,
  );
}

async function generateKeyPair() {
  return await webcrypto.subtle.generateKey(algorithm, false, ["sign"]);
}

async function issueCertificate(issuerKeyPair, serial, subject = null) {
  const commonName = (value) =>
    new pki.AttributeTypeAndValue({
      type: "2.5.4.3",
      value: new asn1.Utf8String({ value }),
    });
  const certificate = new pki.Certificate();
  certificate.version = 2;
  certificate.serialNumber = new asn1.Integer({ value: serial });
  certificate.issuer.typesAndValues.push(commonName(issuerName));
  certificate.subject.typesAndValues.push(
    commonName(subject?.name || issuerName),
  );
  certificate.notBefore.value = new Date();
  const notAfter = new Date();
  notAfter.setUTCFullYear(notAfter.getUTCFullYear() + 1);
  certificate.notAfter.value = notAfter;
  const basicConstraints = new pki.BasicConstraints({ cA: !subject });
  certificate.extensions = [
    new pki.Extension({
      extnID: "2.5.29.19",
      critical: true,
      extnValue: basicConstraints.toSchema().toBER(),
      parsedValue: basicConstraints,
    }),
  ];
  await certificate.subjectPublicKeyInfo.importKey(
    subject?.publicKey || issuerKeyPair.publicKey,
    crypto,
  );
  await certificate.sign(issuerKeyPair.privateKey, algorithm.hash, crypto);
  return certificate;
}

async function signMessage(message, certificate, certificates, privateKey) {
  const { issuer, serialNumber } = certificate;
  const info = new pki.SignerInfo({
    sid: new pki.IssuerAndSerialNumber({ issuer, serialNumber }),
  });
  const data = new pki.SignedData({
    encapContentInfo: new pki.EncapsulatedContentInfo({
      eContentType: pki.ContentInfo.DATA,
      eContent: new asn1.OctetString({ valueHex: message }),
    }),
    signerInfos: [info],
    certificates,
  });
  await data.sign(privateKey, 0, algorithm.hash, undefined, crypto);
  return new pki.ContentInfo({
    contentType: pki.ContentInfo.SIGNED_DATA,
    content: data.toSchema(true),
  });
}
