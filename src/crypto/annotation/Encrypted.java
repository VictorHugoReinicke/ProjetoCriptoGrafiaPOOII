package crypto.annotation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.annotation.ElementType;

/**
 * 
 *  Aqui é a parte de notação
 *  Vai ser utilizado esse Encrypted para poder 
 *  dizer quais atributos criptografar no projeto
 * 
 * 
**/

@Retention(RetentionPolicy.RUNTIME) // Esse faz a classe não esquecer de rodar ele 
@Target(ElementType.FIELD) // Restringe onde a pessoa pode utilizar a notação, no caso só em campos(atributos)
public @interface Encrypted {

}
