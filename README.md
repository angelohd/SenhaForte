        SenhaForte-PHP
    ----------------------

Uma biblioteca simples em PHP para gerar senhas fortes, validar a complexidade e verificar se já foram comprometidas em wordlists públicas (via Have I Been Pwned API em https://haveibeenpwned.com/Passwords), com cache local para melhor performance.

        Funcionalidades
    --------------------------
✅ Geração de senhas fortes e aleatórias
✅ Verificação se a senha atende requisitos de segurança:
    Pelo menos 8 caracteres
    Pelo menos 1 letra maiúscula
    Pelo menos 1 letra minúscula
    Pelo menos 1 número
    Pelo menos 1 caractere especial

✅ Consulta à API pública do HIBP para verificar se a senha já foi descoberta em wordlists
✅ Sistema de cache local para evitar requisições repetidas desnecessárias

        Instalação
    --------------------
composer require seu-usuario/senhaforte

Exemplo de Uso
ver arquivo teste/teste.php
