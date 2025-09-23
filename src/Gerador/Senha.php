<?php
declare(strict_types=1);

namespace Gerador;

class Senha
{
    private string $cacheDir;

    public function __construct(string $cacheDir = __DIR__ . '/../../cache')
    {
        $this->cacheDir = $cacheDir;

        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0777, true);
        }
    }

    private const MAIUSCULAS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const MINUSCULAS = 'abcdefghijklmnopqrstuvwxyz';
    private const NUMEROS = '0123456789';
    private const ESPECIAIS = '!@#$%^&*()-_=+[]{}|;:,.<>?/';

    public function gerarSenha(int $tamanho = 8): string
    {
        if ($tamanho < 8) {
            $tamanho = 8;
        }

        $maiusculas = self::MAIUSCULAS;
        $minusculas = self::MINUSCULAS;
        $numeros = self::NUMEROS;
        $especiais = self::ESPECIAIS;

        // Garantir pelo menos 1 de cada tipo
        $senha = '';
        $senha .= $maiusculas[random_int(0, strlen($maiusculas) - 1)];
        $senha .= $minusculas[random_int(0, strlen($minusculas) - 1)];
        $senha .= $numeros[random_int(0, strlen($numeros) - 1)];
        $senha .= $especiais[random_int(0, strlen($especiais) - 1)];

        $todos = $maiusculas . $minusculas . $numeros . $especiais;
        for ($i = strlen($senha); $i < $tamanho; $i++) {
            $senha .= $todos[random_int(0, strlen($todos) - 1)];
        }

        // usar shuffle seguro: str_shuffle é aceitável aqui (não criptográfico),
        // mas para melhor aleatoriedade podemos embaralhar manualmente:
        $senhaArray = preg_split('//u', $senha, -1, PREG_SPLIT_NO_EMPTY);
        // Fisher-Yates embaralhamento usando random_int
        $n = count($senhaArray);
        for ($i = $n - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            $tmp = $senhaArray[$i];
            $senhaArray[$i] = $senhaArray[$j];
            $senhaArray[$j] = $tmp;
        }

        return implode('', $senhaArray);
    }

    public function verificarSenhaForte(string $senha): bool
    {
        if (strlen($senha) < 8) {
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

        if (!preg_match('/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?\/]/', $senha)) {
            return false;
        }

        return true;
    }

    /**
     * Verifica se a senha já apareceu em wordlists públicas (HIBP)
     * Usa cache local para evitar consultas repetidas
     */
    public function verificarSenhaComprometida(string $senha): bool
    {
        $hash = strtoupper(sha1($senha));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        $cacheFile = $this->cacheDir . "/{$prefix}.cache";

        // Se já temos cache, lê dele
        if (file_exists($cacheFile) && time() - filemtime($cacheFile) < 86400) {
            $resposta = file_get_contents($cacheFile);
        } else {
            $url = "https://api.pwnedpasswords.com/range/" . $prefix;
            $opts = [
                "http" => [
                    "method" => "GET",
                    "header" => "User-Agent: angelohd-senha-forte-php\r\n"
                ]
            ];
            $context = stream_context_create($opts);
            $resposta = file_get_contents($url, false, $context);

            if ($resposta === false) {
                throw new \Exception("Erro ao consultar API HIBP");
            }

            file_put_contents($cacheFile, $resposta);
        }

        // Verifica se o sufixo está na resposta
        foreach (explode("\n", $resposta) as $linha) {
            [$hashSuffix, $count] = explode(":", trim($linha));
            if ($hashSuffix === $suffix) {
                return true; // senha comprometida
            }
        }

        return false;
    }
}
