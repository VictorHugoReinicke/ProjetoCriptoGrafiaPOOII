package crypto.core;

import crypto.annotation.Encrypted;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * 
 * 
 * Essa classe aqui vai ser pra examinar classes em tempo real indetificando e
 * manipulando os campos protegidos Pelo que eu vi, a Java Reflection API vai
 * ser usada
 * 
 * 
 */

public class ReflectionScanner {

	/**
	 *
	 * Método que vai verificar todas as outras classes que for utilizada procurando
	 * pela anotação do @Encrypted
	 *
	 * @param classe A classe que vai ser passada
	 * @return Retorna um array com todos os campos que estão com a anotação
	 *
	 */
	public static List<Field> EscanearCamposProtegidos(Class<?> classe) {
		List<Field> camposEncrypted = new ArrayList<>();

		Field[] fields = classe.getDeclaredFields(); // pega todos os atributos listados nas classes

		for (Field field : fields) {
			if (field.isAnnotationPresent(Encrypted.class)) { // faz um if pra ver se acha a nossa anotação
				camposEncrypted.add(field);
			}
		}

		return camposEncrypted;
	}

	/**
	 * 
	 * Método que pega o valor de um campo vindo de um objeto, usando métodos para
	 * garantir a acessibilidade
	 * 
	 * @param alvo O objeto do qual o valor será extraído
	 * @param O valor do atributo que queremos ler
	 * @return O valor contido no atributo
	 * @throws IllegalAccessException Se o acesso for negado pela JVM
	 */

	public static Object GetValorCampo(Object alvo, Field campo) throws IllegalAccessException {
		// Torna o campo acessível temporariamente caso seja privado
		boolean acessibilidade = campo.canAccess(alvo);
		if (!acessibilidade) {
			campo.setAccessible(true);
		}

		try {
			return campo.get(alvo);
		} finally {
			// Restaura o estado original de visibilidade
			if (!acessibilidade) {
				campo.setAccessible(false);
			}
		}
	}
	/**
     * Usa um set pra colocar um valor dentro de um atributo específico de um objeto e usando o canAccess igual o método GetValorCampo
     *
     * @param alvo O objeto que receberá o valor
     * @param campo O metadado do atributo a ser modificado
     * @param valor O valor a ser injetado
     * @throws IllegalAccessException Se o acesso for negado pela JVM.
     */
	public static void SetValorCampo(Object alvo, Field campo, Object valor) throws IllegalAccessException {
		boolean acessibilidade = campo.canAccess(alvo);
		if (!acessibilidade) {
			campo.setAccessible(true);
		}

		try {
			campo.set(alvo, valor);
		} finally {
			if (!acessibilidade) {
				campo.setAccessible(false);
			}
		}
	}

}
