package crypto.core;

import crypto.annotation.Encrypted;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;



/**
 * 
 * 
 * Essa classe aqui vai ser pra examinar classes em tempo real indetificando e manipulando os campos protegidos
 * Pelo que eu vi, a Java Reflection API vai ser usada
 * 
 * 
 * */

public class ReflectionScanner {

	
	/**
	 *
	 * Método que vai verificar todas as outras classes que for utilizada procurando pela anotação do @Encrypted
	 *
	 * @param classe A classe que vai ser passada
	 * @return Retorna um array com todos os campos que estão com a anotação
	 *
	 * */
	 public static List<Field> EscanearCamposProtegidos(Class<?> classe) {
	        List<Field> camposEncrypted = new ArrayList<>();
	        
	        Field[] fields = classe.getDeclaredFields(); //pega todos os atributos listados nas classes
	        
	        for (Field field : fields) {
	            if (field.isAnnotationPresent(Encrypted.class)) { //faz um if pra ver se acha a nossa anotação
	            	camposEncrypted.add(field);
	            }
	        }
	        
	        return camposEncrypted;
	    }
	
}
