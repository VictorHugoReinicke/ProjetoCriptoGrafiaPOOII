package crypto.core;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import crypto.api.CifraStrategy;


/**
 * 
 * Classe voltada para utilizar a criptografia AES-GCM-256
 * 
 * 
 * */
public class EncriptadorAES implements CifraStrategy {

	 private static final String TRANSFORMATION = "AES/GCM/NoPadding";
	 private static final int TAMANHO_BITS = 128;
	 private static final int TAMANHO_IV_BYTES = 12;
	
	 /**
	  * Construtor padrão explicitado com comentário para documentação Javadoc.
	  */
	    public EncriptadorAES() {
	        super();
	    }
	 
	@Override
	public String encrypt(String textoLimpo, byte[] rawKey) throws Exception {
		if(textoLimpo ==null) return null;
		
		byte[] iv = new byte[TAMANHO_IV_BYTES]; // cria a parte do IV(garante que as mesmas informações não sejam usadas pela mesma senha)
		new SecureRandom().nextBytes(iv);
		
		SecretKeySpec chaveSecreta = new SecretKeySpec(rawKey, "AES");
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE,chaveSecreta , new GCMParameterSpec(TAMANHO_BITS, iv));
		
		byte[] encripta = cipher.doFinal(textoLimpo.getBytes(StandardCharsets.UTF_8));
		
		ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + encripta.length);
        byteBuffer.put((byte) iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(encripta);
		
		return Base64.getEncoder().encodeToString(byteBuffer.array());// converte para base64
	}

	@Override
	public String decrypt(String textoCripto, byte[] rawKey) throws Exception {
		if (textoCripto == null) return null;

        byte[] decodifica = Base64.getDecoder().decode(textoCripto); //decodifica o base64
        ByteBuffer byteBuffer = ByteBuffer.wrap(decodifica);

       
        int ivSize = byteBuffer.get() & 0xFF;
        if (ivSize != TAMANHO_IV_BYTES) {
            throw new SecurityException("Algo foi alterado do original");
        }

        byte[] iv = new byte[ivSize];
        byteBuffer.get(iv);

        byte[] cipherTextBytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherTextBytes);

        
        SecretKeySpec chaveSecreta= new SecretKeySpec(rawKey, "AES");
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, chaveSecreta, new GCMParameterSpec(TAMANHO_BITS, iv)); //Configuração pra acontecer a decriptografia

        
        byte[] textoLimpoBytes = cipher.doFinal(cipherTextBytes);
        return new String(textoLimpoBytes, StandardCharsets.UTF_8);
	}

	@Override
	public String getAlgorithmIdentifier() {
		return "AES-GCM-256-ENVELOPE";
	}

}
