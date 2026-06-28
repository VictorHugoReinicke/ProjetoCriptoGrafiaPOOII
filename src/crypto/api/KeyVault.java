package crypto.api;


/**
 * 
 * Essa vai ser a interface para fornecer a chave 
 * pra CifraStrategy
 * 
 * 
 * */
public interface KeyVault {

	/**
	 * 
	 * @return Um array de bytes que representa a chave de segurança.
	 * @throws Exception Caso ocorra alguma falha
	 * 
	 * */
	byte[] retrieveKey() throws Exception;
	
}
