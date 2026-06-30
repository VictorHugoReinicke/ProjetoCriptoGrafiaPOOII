package crypto.api;

/**
 * Obriga as classes que utilizarem ela ter o encrypt e decrypt
 * Basicamente é por essa classe aqui que as outras vão se comunicar
 * Foquei em usar a Strategy aqui para ter o desacoplamento entre classes 
 */
public interface CifraStrategy {

	/**
	 * 
	 * Encripta um texto limpo e decripta ele.
	 * @param textoLimpo O texto legível que vai ser protegido.
     * @param rawKey A chave simétrica em formato de bytes.
     * @return O texto cifrado codificado (geralmente em Base64).
     * @throws Exception Caso ocorra algum erro durante o processo de cifragem. 
	 */
	 String encrypt(String textoLimpo, byte[] rawKey) throws Exception;
	 
	 /**
	  * Desencripta um texto criptografado utilizando a chave correspondente.
	  * @param textoCripto O texto criptografado (geralmente em Base64).
	  * @param rawKey A chave simétrica em formato de bytes.
	  * @return O texto original decifrado e legível.
	  * @throws Exception Caso ocorra erro de integridade ou chave incorreta.
	  */
	 String decrypt(String textoCripto, byte[] rawKey) throws Exception;
	 
	 /**
	  * Retorna o identificador único do algoritmo (ex: AES-GCM-256).
	  * Útil para fins de auditoria ou seleção dinâmica de estratégias.
	  * @return O nome identificador do algoritmo.
	  */
	 String getAlgorithmIdentifier();
}
