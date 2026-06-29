package crypto.core;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import crypto.annotation.Encrypted;

import crypto.api.CifraStrategy;
import crypto.api.KeyVault;

/**
 * 
 * 
 * Classe responsável por coordenar o fluxo de gravação e leitura de objetos 
 *
 *
 */

public class EnginePersistenciaSegura {

	private final CifraStrategy cifraStrategy;
    private final KeyVault keyVault;
    
	public EnginePersistenciaSegura(CifraStrategy cifraStrategy, KeyVault keyVault) {
		this.cifraStrategy = cifraStrategy;
		this.keyVault = keyVault;
	}
	
	/**
     * Vê todos os atributos de qualquer objeto num mapa para serem guardados em um SQL, os com @Encrypted são criptografados
     *
     * @param entidade O objeto Java de onde estrai os dados.
     * @return Um mapa representando a "linha" da base de dados (coluna -> valor seguro).
     */
	
	public Map<String, Object> persist(Object entidade) {
        if (entidade == null) {
            throw new IllegalArgumentException("Não é possível persistir uma entidade nula");
        }

        Map<String, Object> databaseRow = new HashMap<>();
        Class<?> classe = entidade.getClass();

        try {
            
            byte[] key = keyVault.retrieveKey(); // puxa os valores do byte

            
            for (Field campo : classe.getDeclaredFields()) { // procura todos os campos declarados
                String nomeCampo = campo.getName();
                
                Object valorCru = ReflectionScanner.GetValorCampo(entidade, campo); //pega o valor do campo

                if (valorCru == null) {
                    databaseRow.put(nomeCampo, null);
                    continue;
                }

                
                if (campo.isAnnotationPresent(Encrypted.class)) { //verifica se tem o Encrypted, daí protege
                    if (valorCru instanceof String) {
                        
                        String encryptedValue = cifraStrategy.encrypt((String) valorCru, key);
                        databaseRow.put(nomeCampo, encryptedValue);
                    } else {
                        throw new IllegalArgumentException(
                            "O atributo '" + nomeCampo + "' na classe " + classe.getSimpleName() + 
                            " está marcado com @Encrypted mas não é do tipo String."
                        );
                    }
                } else {
                    databaseRow.put(nomeCampo, valorCru); //campo comum sem nada de especial
                }
            }

            return databaseRow;

        } catch (Exception e) {
            throw new RuntimeException("Falha crítica ao preparar entidade para persistência segura.", e);
        }
    }
    
}
