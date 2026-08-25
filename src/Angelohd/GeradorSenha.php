<?php

declare(strict_types=1);

namespace Angelohd;

/**
 * Classe responsavel pela geracao, validacao e verificacao de senhas fortes.
 * Inclui verificacao contra senhas comprometidas via API do HaveIBeenPwned (HIBP).
 *
 * @author Angelo N. Mwadiavita
 * @license MIT
 */
class GeradorSenha
{
    private string $cacheDir;

    private const MAIUSCULAS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const MINUSCULAS = 'abcdefghijklmnopqrstuvwxyz';
    private const NUMEROS = '0123456789';
    private const ESPECIAIS = '!@#$%^&*()-_=+[]{}|;:,.<>?/£';

    private const REGEX_ESPECIAIS = '/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?\/£]/';

    public function __construct(string $cacheDir = __DIR__ . '/../../cache')
    {
        $this->cacheDir = $cacheDir;

        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0750, true);
        }
    }

    /**
     * Gera uma senha forte com o tamanho especificado.
     */
    public function gerarSenha(int $tamanho = 12): string
    {
        if ($tamanho < 12) {
            $tamanho = 12;
        }

        $senha = '';
        $senha .= self::MAIUSCULAS[random_int(0, strlen(self::MAIUSCULAS) - 1)];
        $senha .= self::MINUSCULAS[random_int(0, strlen(self::MINUSCULAS) - 1)];
        $senha .= self::NUMEROS[random_int(0, strlen(self::NUMEROS) - 1)];
        $senha .= self::ESPECIAIS[random_int(0, strlen(self::ESPECIAIS) - 1)];

        $todos = self::MAIUSCULAS . self::MINUSCULAS . self::NUMEROS . self::ESPECIAIS;
        $lenTodos = strlen($todos);
        while (strlen($senha) < $tamanho) {
            $senha .= $todos[random_int(0, $lenTodos - 1)];
        }

        $senhaArray = preg_split('//u', $senha, -1, PREG_SPLIT_NO_EMPTY) ?: str_split($senha);
        $n = count($senhaArray);
        for ($i = $n - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            [$senhaArray[$i], $senhaArray[$j]] = [$senhaArray[$j], $senhaArray[$i]];
        }

        return implode('', $senhaArray);
    }

    /**
     * Gera varias senhas de uma vez.
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
     * Verifica se a senha e forte segundo regra padrao.
     */
    public function verificarSenhaForte(string $senha): bool
    {
        return $this->validarPoliticaSenha($senha, 12, true);
    }

    /**
     * Valida a senha conforme politica configuravel.
     */
    public function validarPoliticaSenha(string $senha, int $minimo = 12, bool $simbolosObrigatorios = true): bool
    {
        if (strlen($senha) < $minimo) {
            return false;
        }
        if (!preg_match('/[A-Z]/', $senha)) {
            return false;
        }
        if (!preg_match('/[a-z]/', $senha)) {
            return false;
        }
        if (!preg_match('/[0-9]/', $senha)) {
            return false;
        }
        if ($simbolosObrigatorios && !preg_match(self::REGEX_ESPECIAIS, $senha)) {
            return false;
        }
        return true;
    }

    /**
     * Pontua a forca da senha (0 a 10).
     */
    public function pontuarSenha(string $senha): int
    {
        $score = 0;
        $tamanho = strlen($senha);

        if ($tamanho >= 8) {
            $score++;
        }
        if ($tamanho >= 12) {
            $score++;
        }
        if ($tamanho >= 16) {
            $score++;
        }

        if (preg_match('/[A-Z]/', $senha)) {
            $score++;
        }
        if (preg_match('/[a-z]/', $senha)) {
            $score++;
        }
        if (preg_match('/[0-9]/', $senha)) {
            $score++;
        }
        if (preg_match(self::REGEX_ESPECIAIS, $senha)) {
            $score++;
        }

        $tiposPresentes = 0;
        if (preg_match('/[A-Z]/', $senha)) {
            $tiposPresentes++;
        }
        if (preg_match('/[a-z]/', $senha)) {
            $tiposPresentes++;
        }
        if (preg_match('/[0-9]/', $senha)) {
            $tiposPresentes++;
        }
        if (preg_match(self::REGEX_ESPECIAIS, $senha)) {
            $tiposPresentes++;
        }
        if ($tiposPresentes >= 4) {
            $score++;
        }

        if (preg_match('/(.+?)\1{2,}/', $senha)) {
            $score = max(0, $score - 2);
        }

        return min(10, $score);
    }

    /**
     * Gera um hash seguro da senha.
     *
     * @param array<string, int>|null $opcoes Opcoes para o algoritmo de hash
     */
    public function gerarHash(string $senha, ?array $opcoes = null): string
    {
        $algosDisponiveis = password_algos();

        if (in_array('argon2i', $algosDisponiveis, true)) {
            $algo = PASSWORD_ARGON2I;
            $defaultOptions = [
                'memory_cost' => 65536,
                'time_cost' => 4,
                'threads' => 3,
            ];
        } else {
            $algo = PASSWORD_BCRYPT;
            $defaultOptions = [
                'cost' => 12,
            ];
        }

        $options = array_merge($defaultOptions, $opcoes ?? []);

        return password_hash($senha, $algo, $options);
    }

    /**
     * Verifica se a senha digitada corresponde ao hash armazenado.
     */
    public function verificarSenhaUsuario(string $senhaDigitada, string $senhaHashGuardada): bool
    {
        return password_verify($senhaDigitada, $senhaHashGuardada);
    }

    /**
     * Verifica se o hash precisa de rehash (algoritmo ou custo desatualizados).
     */
    public function verificarRehash(string $senha, string $hash): bool
    {
        return password_needs_rehash($senha, PASSWORD_DEFAULT, ['cost' => 12]);
    }

    /**
     * Compara duas senhas com seguranca contra timing attacks.
     */
    public function verificarSenhaIgual(string $senha1, string $senha2): bool
    {
        return hash_equals($senha1, $senha2);
    }

    /**
     * Verifica se a senha foi comprometida (HIBP API).
     * Retorna true se a senha ja foi encontrada em leaks publicos.
     *
     * @throws \RuntimeException Se a consulta a API falhar
     */
    public function verificarSenhaComprometida(string $senha): bool
    {
        $hash = strtoupper(sha1($senha));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        $cacheFile = $this->cacheDir . "/{$prefix}.cache";

        if (file_exists($cacheFile) && time() - filemtime($cacheFile) < 86400) {
            $resposta = file_get_contents($cacheFile);
            if ($resposta === false) {
                throw new \RuntimeException("Erro ao ler cache local: {$cacheFile}");
            }
        } else {
            $url = "https://api.pwnedpasswords.com/range/" . $prefix;
            $opts = [
                "http" => [
                    "method" => "GET",
                    "header" => "User-Agent: ndaysystem-gerador-senha\r\n",
                    "timeout" => 5,
                ],
            ];
            $context = stream_context_create($opts);
            $resposta = file_get_contents($url, false, $context);

            if ($resposta === false) {
                throw new \RuntimeException("Erro ao consultar API HaveIBeenPwned para prefixo: {$prefix}");
            }

            file_put_contents($cacheFile, $resposta);
        }

        foreach (explode("\n", $resposta) as $linha) {
            if (trim($linha) === '') {
                continue;
            }
            [$hashSuffix, $count] = explode(':', trim($linha));
            if ($hashSuffix === $suffix) {
                return true;
            }
        }

        return false;
    }

    /**
     * Remove caches antigos da API HIBP.
     */
    public function limparCacheAntigo(int $dias = 7): int
    {
        $removidos = 0;
        foreach (glob($this->cacheDir . '/*.cache') as $arquivo) {
            if (time() - filemtime($arquivo) > ($dias * 86400)) {
                unlink($arquivo);
                $removidos++;
            }
        }
        return $removidos;
    }

    /**
     * Gera um codigo numerico aleatorio (ex: OTP, token, etc.).
     *
     * @throws \InvalidArgumentException Se tamanho for menor que 1
     */
    public function gerarCodigoNumero(int $tamanho, bool $noLeadingZero = false): string
    {
        if ($tamanho < 1) {
            throw new \InvalidArgumentException("O tamanho do codigo deve ser pelo menos 1.");
        }

        $codigo = $noLeadingZero
            ? (string) random_int(1, 9)
            : (string) random_int(0, 9);

        for ($i = 1; $i < $tamanho; $i++) {
            $codigo .= (string) random_int(0, 9);
        }

        return $codigo;
    }
}
