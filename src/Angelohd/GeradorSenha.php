<?php

declare(strict_types=1);

namespace Angelohd;

/**
 * Classe responsável pela geração, validação e verificação de senhas fortes.
 * Inclui verificação contra senhas comprometidas via API do HaveIBeenPwned (HIBP).
 *
 * @author
 * @license MIT
 */
class GeradorSenha
{
    private string $cacheDir;

    private const MAIUSCULAS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const MINUSCULAS = 'abcdefghijklmnopqrstuvwxyz';
    private const NUMEROS = '0123456789';
    private const ESPECIAIS = '!@#$%^&*()-_=+[]{}|;:,.<>?/£';

    public function __construct(string $cacheDir = __DIR__ . '/../../cache')
    {
        $this->cacheDir = $cacheDir;

        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0777, true);
        }
    }

    /**
     * Gera uma senha forte com o tamanho especificado.
     */
    public function gerarSenha(int $tamanho = 12): string
    {
        if ($tamanho < 8) {
            $tamanho = 8;
        }

        $senha = '';
        $senha .= self::MAIUSCULAS[random_int(0, strlen(self::MAIUSCULAS) - 1)];
        $senha .= self::MINUSCULAS[random_int(0, strlen(self::MINUSCULAS) - 1)];
        $senha .= self::NUMEROS[random_int(0, strlen(self::NUMEROS) - 1)];
        $senha .= self::ESPECIAIS[random_int(0, strlen(self::ESPECIAIS) - 1)];

        $todos = self::MAIUSCULAS . self::MINUSCULAS . self::NUMEROS . self::ESPECIAIS;
        while (strlen($senha) < $tamanho) {
            $senha .= $todos[random_int(0, strlen($todos) - 1)];
        }

        // Embaralhar usando Fisher-Yates com random_int()
        //$senhaArray = preg_split('//u', $senha, -1, PREG_SPLIT_NO_EMPTY);
        $senhaArray = preg_split('//u', $senha, -1, PREG_SPLIT_NO_EMPTY) ?: str_split($senha);
        $n = count($senhaArray);
        for ($i = $n - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            [$senhaArray[$i], $senhaArray[$j]] = [$senhaArray[$j], $senhaArray[$i]];
        }

        return implode('', $senhaArray);
    }

    /**
     * Gera várias senhas de uma vez.
     */
    public function gerarVariasSenhas(int $quantidade, int $tamanho = 12): array
    {
        $senhas = [];
        for ($i = 0; $i < $quantidade; $i++) {
            $senhas[] = $this->gerarSenha($tamanho);
        }
        return $senhas;
    }

    /**
     * Verifica se a senha é forte segundo regras padrão.
     */
    public function verificarSenhaForte(string $senha): bool
    {
        return $this->validarPoliticaSenha($senha, 8, true);
    }

    /**
     * Valida a senha conforme política configurável.
     */
    public function validarPoliticaSenha(string $senha, int $minimo = 12, bool $simbolosObrigatorios = true): bool
    {
        if (strlen($senha) < $minimo)
            return false;
        if (!preg_match('/[A-Z]/', $senha))
            return false;
        if (!preg_match('/[a-z]/', $senha))
            return false;
        if (!preg_match('/[0-9]/', $senha))
            return false;
        if ($simbolosObrigatorios && !preg_match('/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?\/]/', $senha))
            return false;
        return true;
    }

    /**
     * Pontua a força da senha (0 a 6).
     */
    public function pontuarSenha(string $senha): int
    {
        $score = 0;
        if (strlen($senha) >= 8)
            $score++;
        if (strlen($senha) >= 12)
            $score++;
        if (preg_match('/[A-Z]/', $senha))
            $score++;
        if (preg_match('/[a-z]/', $senha))
            $score++;
        if (preg_match('/[0-9]/', $senha))
            $score++;
        if (preg_match('/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?\/]/', $senha))
            $score++;
        return $score;
    }

    /**
     * Gera um hash seguro da senha.
     */
    public function gerarHash(string $senha): string
    {
        return password_hash($senha, PASSWORD_DEFAULT);
    }

    /**
     * Verifica se a senha digitada corresponde ao hash armazenado.
     */
    public function verificarSenhaUsuario(string $senhaDigitada, string $senhaHashGuardada): bool
    {
        return password_verify($senhaDigitada, $senhaHashGuardada);
    }

    /**
     * Compara duas senhas com segurança contra timing attacks.
     */
    public function verificarSenhaIgual(string $senha1, string $senha2): bool
    {
        return hash_equals($senha1, $senha2);
    }

    /**
     * Verifica se a senha foi comprometida (HIBP API).
     * Retorna true se a senha já foi encontrada em leaks públicos.
     */
    public function verificarSenhaComprometida(string $senha): bool
    {
        try {
            $hash = strtoupper(sha1($senha));
            $prefix = substr($hash, 0, 5);
            $suffix = substr($hash, 5);

            $cacheFile = $this->cacheDir . "/{$prefix}.cache";

            if (file_exists($cacheFile) && time() - filemtime($cacheFile) < 86400) {
                $resposta = file_get_contents($cacheFile);
            } else {
                $url = "https://api.pwnedpasswords.com/range/" . $prefix;
                $opts = [
                    "http" => [
                        "method" => "GET",
                        "header" => "User-Agent: ndaysystem-gerador-senha\r\n"
                    ]
                ];
                $context = stream_context_create($opts);
                $resposta = @file_get_contents($url, false, $context);

                if ($resposta === false) {
                    throw new \Exception("Erro ao consultar API HaveIBeenPwned");
                }

                file_put_contents($cacheFile, $resposta);
            }

            foreach (explode("\n", $resposta) as $linha) {
                if (trim($linha) === '')
                    continue;
                [$hashSuffix, $count] = explode(':', trim($linha));
                if ($hashSuffix === $suffix) {
                    return true;
                }
            }

            return false;
        } catch (\Throwable $th) {
            return false;
        }
    }

    /**
     * Remove caches antigos da API HIBP.
     */
    public function limparCacheAntigo(int $dias = 7): void
    {
        foreach (glob($this->cacheDir . '/*.cache') as $arquivo) {
            if (time() - filemtime($arquivo) > ($dias * 86400)) {
                unlink($arquivo);
            }
        }
    }

    /**
     * Gera um código numérico aleatório (ex: OTP, token, etc.)
     */
    public function gerarCodigoNumero(int $tamanho, bool $noLeadingZero = false): string
    {
        $codigo = $noLeadingZero
            ? (string) random_int(1, 9)
            : (string) random_int(0, 9);

        for ($i = 1; $i < $tamanho; $i++) {
            $codigo .= (string) random_int(0, 9);
        }

        return $codigo;
    }
}
