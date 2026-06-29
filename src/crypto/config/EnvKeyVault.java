package crypto.config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import crypto.api.KeyVault;

/**
 * Implementa a KeyVault pra buscar a semente de segurança a partir das variáveis de ambiente do sistema operacional ou da JVM,
 * derivando uma chave criptográfica forte de 256 bits através de SHA-256.
 */

public class EnvKeyVault implements KeyVault {

	private static final String ENV_VAR_NOME = "KEY_ORM";
	private static final String SYS_NAME = "crypto.master.key";
	private static final String DEFAULT_FALLBACK_SEED = "FallBackSeedEvitandoCairPorFavorMeDa1056!";

	@Override
	public byte[] retrieveKey() throws Exception {
		String seed = System.getenv(ENV_VAR_NOME); //tenta pegar a senha vinda do próprio pc

        if (seed == null || seed.trim().isEmpty()) {
            seed = System.getProperty(SYS_NAME); // se não ele tenta buscar nos arquivos reserva
        }

        if (seed == null || seed.trim().isEmpty()) {// caso tudo de errado nessa vida, usa um fallback pra desenvolvimento
            System.err.println("[AVISO DE SEGURANÇA] Nenhuma chave mestra configurada no ambiente. Utilizando semente de fallback!");
            seed = DEFAULT_FALLBACK_SEED;
        }

        return deriveKeyFromSeed(seed);
	}

	private byte[] deriveKeyFromSeed(String seed) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(seed.getBytes(StandardCharsets.UTF_8));
    }
}
