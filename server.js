const fs = require('fs')
const path = require("path");
const https = require('https')
const multer  = require('multer')
const express = require('express')
const request = require('request');
const forge = require('node-forge');
const upload = multer({ dest: 'uploads/' });
const axios = require('axios').default;
var chilkat = require('@chilkat/ck-node12-win64'); 
//var chilkat = require('@chilkat/ck-node14-win64'); 

const app = express()

app.get('/', (req, res) => {
	res.send('<a href="authenticate">accesse utilizando um certificado e-CNPJ</a>')
})
app.post('/autenticacaoComArquivo', upload.single('avatar'), function(req, res, next) {
    const file = req.file;
    const nomeExtensao = file.originalname.split(".");
    const extensao = nomeExtensao[1];
    const destination = file.destination;
    const filename = file.filename;
    const pathLocalSemExtensao = destination+filename;
    const resolvido = path.resolve(pathLocalSemExtensao);
    const pathCompletoSemExtensao = resolvido.replace(/\\/g, '/');
    const pathCompletoComExtensao = pathCompletoSemExtensao+"."+extensao;
    fs.rename(pathCompletoSemExtensao, pathCompletoComExtensao, err => console.log(err));
    console.log("pathCompletoComExtensao->"+pathCompletoComExtensao)    
    const senha = req.body.pfxp;
    console.log("senha->"+senha)
    var p12 = fs.readFileSync(pathCompletoComExtensao, 'binary');
    var p12Asn1 = forge.asn1.fromDer(p12, false);   
    var p12Parsed = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, senha);
    //console.log("p12Parsed->"+JSON.stringify(p12Parsed))
    const attributes = p12Parsed.safeContents[0].safeBags[0].cert.subject.attributes;
    const atributo = attributes.filter(atributo=> atributo.shortName === "CN");
    const certSubjectCN = atributo[0].value;
    const certSubjectaltname = null;

    const json = getInformmacaoCertificado(certSubjectCN, certSubjectaltname, pathCompletoComExtensao, senha);
    const start = async function(json){
        const resultado = await sendPostRequest(json);
        console.log("start1=>"+resultado);
        res.send(resultado);
    } 
    start(json);
})
app.get('/authenticate', (req, res) => {

	const cert = req.connection.getPeerCertificate();
    const certi = JSON.stringify(cert);
    //console.log("certi->"+certi);
    console.log("req.client.authorized->"+req.client.authorized)

	if (certi.length <= 2) {
        return res.status(401).send(`Favor informar um certificado para assinar.`);
    } 
    const certSubjectCN = cert.subject.CN;
    const certSubjectaltname = "cert.subjectaltname";
    const localArquivoPFX = "C:/Users/Fernando/Desktop/Nova pasta/Assinatura-PKCS12-servidor-node/alice.p12";
    const senha = "";
    const json = getInformmacaoCertificado(certSubjectCN, certSubjectaltname, localArquivoPFX, senha);
    res.send(json);
    /*
    const start = async function(json){
        const resultado = await sendPostRequest(json);
        console.log("start3=>"+resultado);
        res.send(resultado);
    } 
    start(json);
    */
})

const opts = { key: fs.readFileSync('server_key.pem'), 
			   cert: fs.readFileSync('server_cert.pem'), 
			   ca: fs.readFileSync('server_cert.pem'), 
			   requestCert: true, 
			   rejectUnauthorized: false
             }
https.createServer(opts, app).listen(9999)

function realizaChamadaCorDapp(json) {

    const cordaResposta = request.post('http://localhost:8080/criaConta',
                                        { json: json },
                                        function (error, response, body) {

                                            if(error){
                                                console.log("error->"+JSON.stringify(error));
                                                return error;
                                            }
                                            if (!error && response.statusCode == 200) {
                                                console.log("salvou na blockchain com sucesso->"+body);
                                                return body;                                                
                                            }
                                            console.log("response->"+JSON.stringify(response));
                                            return JSON.stringify(response);
                                        });
    return cordaResposta;
}
const sendPostRequest = async (json) => {
    try {
        const resp = await axios.post('http://localhost:8080/criaConta', json);
        console.log("resp.data->"+resp.data);
        return resp.data;
    } catch (err) {
        // Handle Error Here
        console.error("err->"+err);
        const erro = JSON. stringify(err);
        if(erro.includes("createError")){
            return "Conta já existe";
        }else{
            return err;
        }
    }
};
function getInformmacaoCertificado(certSubjectCN, certSubjectaltname, localArquivoPFX, senha) {

	const razaoCnpj = certSubjectCN.split(":");
    var cnpj = razaoCnpj[1];
    if(cnpj == null){
        cnpj = " ";
    }
    var email = " ";
    if(certSubjectaltname != null){
        const emails = certSubjectaltname.split(",");
        email = emails[0].replace("email:","");
    }
	var assinatura = getAssinatura(localArquivoPFX, senha, certSubjectCN);
    //console.log("assinatura->"+assinatura)
    
	const json = {empresa:razaoCnpj[0], cnpj:cnpj, email:email, tipoAutorizacao:"Autorização compra token XYZ", assinatura:assinatura}
	return json;
}

function getAssinatura(localArquivoPFX, senha, certificadoEscolhido) {

    var certStore = new chilkat.CertStore();
    var success = certStore.LoadPfxFile(localArquivoPFX, senha);
    if (success !== true) {
        console.log(certStore.LastErrorText);
        return;
    }
    var cert = certStore.FindCertBySubject(certificadoEscolhido);
    //console.log("cert->"+JSON.stringify(cert));
    if (certStore.LastMethodSuccess == false) {
        console.log(certStore.LastErrorText);
        return;
    }
    var pkey = cert.ExportPrivateKey();
    //console.log("pkey->"+JSON.stringify(pkey));
    if (cert.LastMethodSuccess == false) {
        console.log(cert.LastErrorText);
        return;
    }
    var pkeyXml = pkey.GetXml();
    var rsa = new chilkat.Rsa();
    success = rsa.ImportPrivateKey(pkeyXml);
    if (success !== true) {
        console.log(rsa.LastErrorText);
        return;
    }
    rsa.EncodingMode = "hex";
    //pode dar erro se o rsa de verificação da assinatura de outra aplicação for diferente de LittleEndian
    //true para little-endian ou false para big-endian byte ordering
    rsa.LittleEndian = false;
    var mensagem = "12345";
    //assina o texto usando: ["sha-1", "sha-256", "md2", "md5"]
    const assinado = rsa.SignStringENC(mensagem,"sha-1");
    //console.log("assinado->"+assinado)
    return assinado;

}
