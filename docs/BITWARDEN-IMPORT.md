# Importação de passkeys Bitwarden

## Estado da integração

Este primeiro incremento implementa **importação gráfica de cópias locais** a
partir de um JSON oficial. Não implementa login, conta conectada, histórico
persistente de sincronização ou agendamento. O Bitwarden não é acessado pelo
Linux Passkey nesta versão; não há senha mestra, token ou sessão Bitwarden para
armazenar. Não é necessário instalar `bw`.

Os bloqueios para sincronização conectada continuam registrados na
[pesquisa das interfaces oficiais](BITWARDEN-INTERFACES.md): o CLI pode gravar
tokens sem cifra em JSON, e seu estado não comprova o bloqueio do desktop.
Isso não foi contornado com endpoints privados nem apresentado como resolvido.

## Instalação no CachyOS/Arch com Niri

Dependências já usadas pelo projeto:

```sh
sudo pacman -S --needed python python-gobject python-cryptography gtk4 libadwaita libsecret publicsuffix-list polkit make gettext
```

É necessário um provedor Secret Service, como GNOME Keyring, desbloqueado na
sessão, e um agente polkit funcional no Niri. A extensão GNOME não é necessária.
Se as credenciais existentes usam backend de arquivo, a importação ficará
indisponível: esta versão não migra a chave mestra nem troca seu backend.

Instale o aplicativo e o daemon **da mesma revisão** e recarregue a unidade:

```sh
sudo make install-app install-locale
systemctl --user daemon-reload
systemctl --user restart linux-passkey.service
linux-passkey
```

Uma interface nova conectada a um daemon antigo não poderá chamar
`ImportBitwarden`. Feche e reabra o aplicativo depois da instalação. Instalar
ou atualizar o programa não importa credenciais automaticamente.

## Como importar

1. No aplicativo oficial Bitwarden, exporte os dados individuais em formato
   **JSON não criptografado**. CSV não transporta as chaves das passkeys.
2. Abra o Linux Passkey e escolha **Settings → Integrations → Bitwarden**.
3. Use **Choose JSON…** e selecione o arquivo local. A leitura e validação
   acontecem fora da thread gráfica; limite de 16 MiB e 1000 passkeys.
4. Confira os sites/contas na prévia e os motivos das entradas recusadas.
   A prévia mostra até 20 entradas por categoria, informando o total do lote.
5. Confirme **Import Compatible Passkeys**, aprove o prompt de importação e
   confirme sua identidade pelo agente polkit. Recusar ou cancelar não importa
   o lote. Biometria depende de sua configuração PAM/fprintd.
6. As cópias aparecem na lista com um ícone de importação e origem
   **Bitwarden (local copy)** nos detalhes. O resultado da operação aparece
   na página de integrações enquanto essa janela permanecer aberta.

O JSON exportado contém chaves privadas e pode conter senhas e outros dados do
cofre. O programa não faz outra cópia desse arquivo no disco. Remova o arquivo
de exportação após o uso conforme sua política de armazenamento; não o envie
para issues, logs, testes ou este repositório. A aplicação não promete apagar
retroativamente cópias, backups ou blocos já escritos pelo exportador.

## Compatibilidade e validação

- Chave privada PKCS#8 DER em base64url, ES256/ECDSA P-256.
- Credential ID UUID ou `b64.` conforme a representação do Bitwarden, preservado
  como os bytes originais, com limite de 1023 bytes. Nunca é gerado outro ID.
- RP ID válido e não público, user handle de 1–64 bytes, data com timezone,
  metadados de tamanho limitado e credencial descobrível.
- Somente contador de assinatura `"0"`. Credenciais antigas com contador
  positivo são recusadas para evitar divergência entre autenticadores.
- A origem Bitwarden comprovada na pesquisa usa BE=BS=true; as cópias mantêm
  essa semântica. Flags explicitamente contraditórias são recusadas. Isso não
  é um importador genérico de arquivos de outros fabricantes.
- EdDSA/Ed25519, JSON criptografado, CXF/CXP, ZIP e contadores positivos não são
  suportados por este importador. As passkeys locais EdDSA continuam funcionando.
- O seed PRF/hmac-secret original não é exportado por esse formato; não se
  afirma continuidade de PRF em cópias importadas.

A importação força credProtect=3: o uso da cópia exige verificação local.
Solicitações CTAP sem UV podem não encontrar essas credenciais; o cliente
precisa solicitar UV. Origem e RP continuam sendo validados a cada operação
WebAuthn. Senha/biometria Linux não desbloqueia o Bitwarden.

## Duplicatas, conflitos e exclusões

Reimportar a mesma identidade, RP, handle e chave não cria outra cópia nem
sobrescreve metadados/estatísticas locais. Um ID existente com chave, RP,
handle ou origem diferente aborta o lote inteiro; a mensagem não contém chaves.
Conflitos não têm resolução destrutiva automática.

Entradas de formato incompatível são recusadas individualmente e aparecem na
prévia. O subconjunto válido só é gravado após confirmação, em uma transação.
Falhas antes da troca atômica do arquivo preservam o estado anterior na memória
e no disco. Uma falha depois do commit pode ser resolvida reimportando o mesmo
lote, pois a operação é idempotente.

As passkeys preexistentes são mantidas, inclusive quando pertencem ao mesmo RP
e usuário. Use o botão de exclusão da lista para remover uma cópia importada.
Isso não exclui a original no Bitwarden nem revoga o cadastro no site.
Uma importação manual futura pode recriar uma cópia excluída; não há ainda
reconciliação remota, tombstones ou detecção de remoções.

Não há conexão para desconectar nesta versão. Bloquear o Bitwarden, remover um
item remoto ou revogar uma sessão **não revoga as cópias já importadas**. Essas
passkeys são sincronizáveis copiadas para armazenamento local cifrado, não
chaves privadas vinculadas ao hardware do notebook.

## Armazenamento, autorização e migração

O mesmo arquivo `~/.local/share/linux-passkey/credentials.enc` guarda registros
externos e as chaves privadas normalizadas, dentro do envelope AES-256-GCM
existente e sob a mesma chave mestra no keyring. Não há outro banco de chaves.
Metadados públicos têm projeção explícita; chaves não aparecem em
`ListCredentials`, status, detalhes da interface ou respostas de importação.

O IPC usa um memfd selado e imutável enviado como descritor Unix. Chaves e
conteúdo do cofre não são argumentos de shell nem strings em chamadas D-Bus.
O daemon lê um lote limitado, exige consentimento próprio e polkit, rejeita
jobs concorrentes e observa a desconexão do remetente. O booleano de autorização
nunca vem do cliente. Erros criptográficos são sanitizados; não se registram
exports, chaves ou sessões em logs.

Antes da primeira importação, o leitor aceita o formato v1 existente. No
primeiro commit de dados externos, grava formato **v2**, mantendo os IDs locais
inalterados e salvando o ciphertext v1 anterior em `credentials.enc.pre-import`
(0600), quando existia um arquivo anterior. Não há snapshot se o cofre estava
vazio e ainda não tinha arquivo. Não é uma rotação da chave mestra.

O programa original não lê v2 e falha fechado. Não execute as duas versões
como escritores do mesmo cofre. Para downgrade, pare o daemon e preserve uma
cópia do arquivo v2 atual antes de qualquer restauração. Restaurar o snapshot
exclui as mudanças posteriores da visão restaurada e só funciona se a chave
mestra não foi girada; exige decisão explícita. O programa não faz downgrade
nem restauração automática. Os registros locais anteriores continuam
utilizáveis no programa novo, sem migração de seus IDs.

O lock do store é por processo e o nome D-Bus limita o daemon a uma instância
por barramento. Não são suportados escritores em barramentos distintos usando
o mesmo diretório. A escrita usa o helper atômico existente, sem prometer uma
garantia nova contra perda de energia além da persistência desse helper.

Secret Service e polkit não isolam totalmente processos hostis do mesmo UID,
root ou um desktop comprometido. Chaves precisam existir na memória durante
uso; Python não oferece garantia de zeroização de todas as cópias. O keyring
ser bloqueado após a abertura não elimina as chaves já carregadas pelo daemon.

## Validação e revisão de segurança

Os testes usam apenas credenciais geradas para teste. O servidor `Fido2Server`
recebe a chave pública conhecida **antes** da importação e verifica asserções
pelos caminhos plataforma e CTAPHID: ID original, assinatura, RP, user handle,
UP/UV, BE/BS e contador zero. Isso comprova uso da chave importada, não uma
nova credencial substituta. Ainda não foi feito um teste contra conta Bitwarden
descartável ou um site real; não se declara interoperabilidade universal.

Também são testados parsing e rejeições, importação parcial, duplicatas,
conflitos, coexistência com passkeys locais, reabertura do store, snapshot v1,
rollback por falha de disco, descritores imutáveis, projeção pública, ausência
de chave em logs, confirmação negada, verificação negada/desabilitada,
cancelamento, concorrência e o cliente assíncrono da interface.

Revisão de segurança deste incremento:

| Área | Resultado |
|---|---|
| Autorização | Verificação no daemon, aprovação explícita, keyring e polkit obrigatórios, cancelamento antes do commit |
| Criptografia | Reutiliza AES-GCM/HKDF e parsing do `cryptography`; nenhum algoritmo ou backend novo |
| Exposição | Não usa CLI, senha mestra ou tokens; FD selado, projeção pública explícita, exceções sanitizadas |
| Integridade | Lote validado, conflito aborta a transação, snapshot cifrado, memória trocada após persistência |
| Injeção | Sem shell, endpoints ou execução de dados importados; JSON limitado e chaves duplicadas recusadas |
| UI | Leitura em worker, labels escapados na lista, prévia sem markup e sem material privado |
| Rede/SSRF | Não há acesso remoto neste incremento; sandbox do daemon mantido |
| Dependências | Nenhuma dependência de runtime adicionada; não se afirma auditoria completa de CVEs das dependências existentes |

Execute `make check` e `make lint` no ambiente de desenvolvimento. O teste de
inicialização GTK no Niri abre apenas a página, sem autorizar importação nem
usar credenciais do usuário. O teste automatizado de polkit usa um verificador
de teste; não comprova funcionamento de um leitor biométrico físico.

Resultado desta revisão: `make check` passou com **168 testes** (43 avisos de
depreciação GLib/PyGObject); `make lint` passou, com o aviso já existente sobre
a referência externa do DTD polkit, validada pelo DTD local. A página GTK foi
inicializada na sessão Niri sem importar dados. Nenhuma dependência de runtime
foi adicionada.
