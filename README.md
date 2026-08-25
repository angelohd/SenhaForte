        SenhaForte-PHP
    ----------------------

Uma biblioteca PHP para gerar senhas fortes, validar complexidade e verificar se ja foram comprometidas em wordlists publicas (via Have I Been Pwned API), com cache local para melhor performance.

[![PHP](https://img.shields.io/badge/php-%3E%3D7.4-8892BF.svg)](https://php.net)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

        Funcionalidades
    --------------------------
- Geracao de senhas fortes e aleatorias (minimo 12 caracteres)
- Validacao de complexidade com politica configuravel
- Verificacao contra senhas comprometidas (HIBP API)
- Cache local com expiracao de 24h
- Hashing seguro com Argon2i (ou Bcrypt como fallback)
- Geracao de codigos numericos aleatorios (OTP)
- Comparacao segura contra timing attacks

        Instalacao
    --------------------

composer require angelohd/senha-forte

        Exemplo de Uso
    --------------------

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Angelohd\GeradorSenha;

$gerador = new GeradorSenha();

// Gerar senha forte (16 caracteres)
$senha = $gerador->gerarSenha(16);
echo "Senha: {$senha}\n";

// Verificar se e forte
if ($gerador->verificarSenhaForte($senha)) {
    echo "Senha forte!\n";
}

// Pontuacao de 0 a 10
$score = $gerador->pontuarSenha($senha);
echo "Score: {$score}/10\n";

// Hash para armazenamento
$hash = $gerador->gerarHash($senha);

// Verificar senha contra hash
$gerador->verificarSenhaUsuario($senha, $hash);

// Verificar se senha foi comprometida (HIBP)
try {
    if ($gerador->verificarSenhaComprometida($senha)) {
        echo "Senha comprometida!\n";
    }
} catch (\RuntimeException $e) {
    echo "Erro HIBP: " . $e->getMessage() . "\n";
}

// Gerar OTP
$otp = $gerador->gerarCodigoNumero(6, true);
echo "OTP: {$otp}\n";
```

        Metodos Disponiveis
    --------------------

| Metodo | Descricao |
|--------|-----------|
| `gerarSenha(int $tamanho)` | Gera senha forte aleatoria |
| `verificarSenhaForte(string $senha)` | Verifica se atende politica padrao |
| `validarPoliticaSenha(string, int, bool)` | Valida com regras configuraveis |
| `pontuarSenha(string $senha)` | Retorna score de 0 a 10 |
| `gerarHash(string $senha, ?array $opts)` | Gera hash seguro (Argon2i/Bcrypt) |
| `verificarSenhaUsuario(string, string)` | Verifica senha contra hash |
| `verificarRehash(string, string)` | Verifica se hash esta desatualizado |
| `verificarSenhaIgual(string, string)` | Comparacao segura (timing-safe) |
| `verificarSenhaComprometida(string)` | Consulta HIBP API |
| `limparCacheAntigo(int $dias)` | Remove caches expirados |
| `gerarCodigoNumero(int, bool)` | Gera OTP numerico |

        Licenca
    --------------------
MIT
