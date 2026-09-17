# Exfiltração de Streams de Áudio do Netflix via Interceptação de Rede pelo Chrome DevTools Protocol

**Data de Divulgação:** 2026-09-16
**Identificador CVE:** Atribuição Pendente (submetido ao MITRE em 2026-09-16)
**CWE:** CWE-311 (Ausência de Criptografia de Dados Sensíveis), CWE-693 (Falha de Mecanismo de Proteção)
**Severidade:** Média
**Status:** Sem correção (fornecedor notificado)
**Plataforma Afetada:** Plataforma de streaming Netflix (todas as regiões, todos os planos de assinatura)
**Classe do Ataque:** Interceptação de Stream de Mídia Desprotegido, Lacuna de Política de DRM
**CPE:** cpe:2.3:a:netflix:netflix:*:*:*:*:*:web:*:*

---

## Autores

**Juan Mathews Rebello Santos**
Pesquisador de Segurança
LinkedIn: https://www.linkedin.com/in/juan-mathews-rebello-santos-/
Website: http://juanmathewsrebellosantos.com/

**Jhonata Fernandes Cordeiro**
Pesquisador de Segurança
LinkedIn: https://www.linkedin.com/in/jhonata-fernandes-cordeiro-a887bb293/

---

## Pontuação CVSS

### CVSS v3.1

**Pontuação Base: 5.0 (Média)**
**Vetor:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N`

| Métrica | Valor | Justificativa |
|---|---|---|
| Vetor de Ataque (AV) | Local (L) | O exploit requer execução de processo na máquina que executa a sessão autenticada do Chrome |
| Complexidade do Ataque (AC) | Baixa (L) | Sem condições de corrida, sem requisitos de temporalização, sem configuração especial além da exposição da porta CDP |
| Privilégios Necessários (PR) | Baixos (L) | Conta de usuário local padrão suficiente para executar narr.exe e acessar a porta TCP 9222 |
| Interação do Usuário (UI) | Necessária (R) | Um usuário autenticado no Netflix deve navegar até o título alvo e reproduzi-lo no Chrome |
| Escopo (S) | Inalterado (U) | O impacto é limitado ao conteúdo de áudio do Netflix acessível pela sessão autenticada |
| Impacto na Confidencialidade (C) | Alto (H) | Trilha de áudio completa de qualquer título Netflix acessível é exfiltrada em texto claro |
| Impacto na Integridade (I) | Nenhum (N) | Nenhum dado é modificado |
| Impacto na Disponibilidade (A) | Nenhum (N) | Nenhuma condição de negação de serviço |

**Derivação da Pontuação:**

```
ISCBase         = 1 - [(1 - 0.56) * (1 - 0.00) * (1 - 0.00)] = 0.5600
ISC (Inalterado)= 6.42 * 0.5600 = 3.5952
Explorabilidade = 8.22 * AV(0.55) * AC(0.77) * PR(0.62) * UI(0.62) = 1.3382
PontuaçãoBase   = Roundup(min(3.5952 + 1.3382, 10)) = Roundup(4.9334) = 5.0
```

---

### CVSS v4.0

**Pontuação Base: 4.8 (Média)**
**Vetor:** `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`

| Métrica | Valor | Justificativa |
|---|---|---|
| Vetor de Ataque (AV) | Local (L) | Requer execução de código local na máquina alvo |
| Complexidade do Ataque (AC) | Baixa (L) | Sem condições especiais de exploit |
| Requisitos de Ataque (AT) | Nenhum (N) | Sem pré-requisitos além do Chrome com CDP habilitado |
| Privilégios Necessários (PR) | Baixos (L) | Acesso de usuário local padrão para executar um processo e abrir uma conexão TCP |
| Interação do Usuário (UI) | Passiva (P) | O usuário alvo deve estar passivamente engajado na reprodução normal de conteúdo Netflix |
| Confidencialidade do Sistema Vulnerável (VC) | Alta (H) | Conteúdo de áudio do Netflix totalmente exposto em texto claro |
| Integridade do Sistema Vulnerável (VI) | Nenhuma (N) | Nenhuma modificação de dados no sistema vulnerável |
| Disponibilidade do Sistema Vulnerável (VA) | Nenhuma (N) | Nenhum impacto na disponibilidade |
| Confidencialidade do Sistema Subsequente (SC) | Nenhuma (N) | Nenhum impacto lateral em outros sistemas |
| Integridade do Sistema Subsequente (SI) | Nenhuma (N) | Nenhum impacto lateral |
| Disponibilidade do Sistema Subsequente (SA) | Nenhuma (N) | Nenhum impacto lateral |

**Derivação das Classes de Equivalência (EQ):**

```
EQ1 (AV, PR, UI): AV:L, PR:L, UI:P -> Nível 2 (nenhum é :N)
EQ2 (AC, AT)    : AC:L, AT:N        -> Nível 0 (condições de ataque mais favoráveis)
EQ3 (VC, VI, VA): VC:H              -> Nível 0 (alto impacto de confidencialidade no sistema vulnerável)
EQ4 (SC, SI, SA): SC:N, SI:N, SA:N  -> Nível 3 (sem impacto no sistema subsequente)
EQ5 (E)         : E:P               -> Nível 1 (PoC público disponível, sem exploração ativa)
EQ6 (CR, IR, AR): valores padrão    -> Nível 1 (requisitos de linha de base médios)
MacroVetor      : 2-0-0-3
PontuaçãoBase   : 4.8 (Média)
```

**Métricas Suplementares:**

| Métrica | Valor |
|---|---|
| Maturidade do Exploit (E) | Prova de Conceito (P) |
| Automatizável (AU) | Não |
| Recuperação (R) | Automática |
| Densidade de Valor (VD) | Difusa |
| Esforço de Resposta à Vulnerabilidade (RE) | Baixo |
| Urgência do Fornecedor (U) | Clara |

---

## Classificação de Fraqueza

| ID CWE | Nome | Aplicabilidade |
|---|---|---|
| CWE-311 | Ausência de Criptografia de Dados Sensíveis | Os conjuntos de adaptação de áudio não são marcados para criptografia CENC no descritor ContentProtection do manifesto DASH |
| CWE-693 | Falha de Mecanismo de Proteção | O DRM Widevine é implantado para trilhas de vídeo, mas não aplicado a trilhas de áudio, criando uma lacuna de política na arquitetura de proteção de conteúdo |
| CWE-319 | Transmissão de Informações Sensíveis em Texto Claro | Os payloads de segmentos de áudio são transmitidos como containers fMP4 em texto claro via entrega por CDN sem criptografia na camada de conteúdo |

---

## Resumo

Este documento descreve uma prova de conceito (PoC) que demonstra a exfiltração de streams de conteúdo de áudio da plataforma Netflix por meio da interceptação de respostas de rede pelo Chrome DevTools Protocol (CDP). A vulnerabilidade surge de uma lacuna arquitetural no modelo de proteção de conteúdo da Netflix: enquanto as trilhas de vídeo são criptografadas sob o DRM Widevine (Nível 1 e Nível 3), as trilhas de áudio são servidas como containers MPEG-4 Audio em texto claro e podem ser baixadas integralmente sem nenhuma etapa de descriptografia.

O ataque não requer a exploração de uma vulnerabilidade de corrupção de memória, nenhum driver em modo kernel e nenhuma engenharia reversa de binários proprietários. Ele abusa de uma interface legítima de automação de navegador contra uma sessão Netflix autenticada e ativa.

---

## Descrição da Vulnerabilidade

### Causa Raiz

O Netflix entrega mídia por meio de um pipeline de streaming de taxa de bits adaptativa baseado em MPEG-DASH. Tanto segmentos de vídeo quanto de áudio são requisitados pelo navegador como requisições HTTP de intervalo direcionadas a recursos hospedados em CDN. O padrão de URL para essas requisições de segmento é:

```
https://<cdn>.nflxvideo.net/...?nflx-...#/range/0-<N>
```

Os segmentos de vídeo são criptografados com Widevine Content Encryption (CENC). As chaves de criptografia são negociadas entre o CDM (Content Decryption Module) Widevine do navegador e o servidor de licenças da Netflix por meio de um handshake EME (Encrypted Media Extensions). A descriptografia ocorre dentro de um ambiente de execução confiável dentro do navegador, e os frames em texto claro nunca são expostos ao processo principal nem ao JavaScript.

Os segmentos de áudio não recebem o mesmo nível de proteção. As trilhas de áudio entregues ao navegador ou não são criptografadas ou são protegidas por uma configuração Widevine que permite passagem em texto claro para a trilha de codec de áudio (AAC, xHE-AAC). Como resultado, quando o navegador realiza um HTTP GET para um segmento de áudio, os bytes de áudio brutos na resposta são acessíveis a qualquer observador com visibilidade na camada de rede do navegador.

### Superfície de Ataque

O Chrome DevTools Protocol fornece uma interface programática para os internos do Chrome. Quando o Chrome é iniciado com a flag `--remote-debugging-port=9222`, ele expõe um endpoint WebSocket que permite que processos externos assinem eventos do navegador, incluindo o evento `Network.responseReceived`. Esse evento dispara para cada resposta HTTP que o navegador processa, incluindo requisições de segmentos de mídia.

Ao se conectar ao CDP e assinar o `Network.responseReceived`, um atacante com acesso local à máquina pode observar todas as URLs de mídia conforme elas são requisitadas pelo player Netflix. Como os segmentos de áudio estão em texto claro, as URLs observadas podem ser buscadas independentemente com um cliente HTTP padrão, reconstruindo a trilha de áudio completa sem nenhum bypass de DRM.

### Descoberta Secundária: Re-busca Não Autenticada via CDN

As URLs de segmento CDN observadas via CDP não requerem nenhuma credencial de sessão Netflix para re-busca. Um HTTP GET emitido sem nenhum cookie, cabeçalho de Authorization ou token de sessão retorna o segmento de áudio completo com HTTP 200. Isso confirma que a URL CDN é o único mecanismo de controle de acesso para entrega de conteúdo de áudio, e que a interceptação da URL é suficiente para exfiltração completa do conteúdo.

---

## Prova de Conceito

### Ambiente

| Componente | Detalhe |
|---|---|
| Sistema Operacional | Windows 10/11 (x64) |
| Navegador | Google Chrome 110 ou superior |
| Porta CDP | 9222 (configurável) |
| Conta Netflix | Qualquer sessão autenticada válida |
| Dependências | Go 1.24 (apenas para compilação), Chrome |

### Fluxo do Ataque

```
[Processo do Atacante]
      |
      |-- Inicia Chrome com --remote-debugging-port=9222
      |-- Autentica no Netflix no navegador (interação do usuário)
      |-- Navega o navegador para a URL do título Netflix alvo
      |
      v
[WebSocket CDP do Chrome ws://127.0.0.1:9222]
      |
      |-- Assina: Network.enable
      |-- Assina: Network.responseReceived
      |
      v
[Player Netflix carrega o título]
      |-- Navegador envia requisição de manifesto DASH
      |-- Navegador envia requisições de intervalo para segmentos de vídeo (criptografados Widevine)
      |-- Navegador envia requisições de intervalo para segmentos de áudio (texto claro)
      |
      v
[Evento Network.responseReceived dispara para cada segmento]
      |
      |-- Filtra URLs contendo o padrão /range/0-
      |-- Sonda os primeiros 3000 bytes da resposta para identificar o codec (parser de caixas MPEG-4 Audio)
      |-- Se áudio: baixa o corpo completo da resposta, escreve em disco
      |-- Se vídeo: descarta (criptografado Widevine, impossível de reproduzir sem chaves CDM)
```

### Arquivos-Chave do Código Fonte

A implementação do PoC está localizada em `src/`. Os componentes críticos são:

**`src/nflx.go` -- Assinatura de eventos CDP e interceptação de URL**

A função `isMediaURL` identifica URLs candidatas correspondendo ao segmento de caminho `/range/0-`:

```go
func isMediaURL(u string) bool {
    return strings.Contains(u, "/range/0-")
}
```

O método `Listen` assina o `Network.responseReceived` e emite URLs interceptadas em um canal:

```go
responseReceived, err := c.Network.ResponseReceived(ctx)
// ...
if isMediaURL(ev.Response.URL) {
    events <- event{MediaUrlReceivedEvent, []byte(ev.Response.URL)}
}
```

**`src/queue.go` -- Discriminação áudio/vídeo e download não autenticado via CDN**

O downloader lê os primeiros 3000 bytes de cada stream interceptado e os passa para `probeFileFormat`. Streams de áudio são persistidos; streams de vídeo criptografados são descartados:

```go
isAudio, fInfo, err := probeFileFormat(header)
if !isAudio {
    return nil  // segmentos de vídeo são criptografados Widevine; descartar
}
```

A re-busca é realizada sem nenhuma credencial de sessão Netflix:

```go
resp, err := http.Get(srcURL)  // sem cookies, sem cabeçalhos de autenticação
```

**`src/probe.go` -- Parser de caixas de container MPEG-4**

Analisa as caixas `ftyp`, `mdat` e `moof` a partir de bytes brutos para determinar se o container contém uma trilha de áudio ou vídeo, e se o codec é AAC ou xHE-AAC.

---

## Impacto

Um atacante com acesso local a uma máquina executando uma sessão Netflix autenticada pode silenciosamente exfiltrar todo o conteúdo de áudio de qualquer título Netflix como MPEG-4 Audio em texto claro, sem acionar nenhuma imposição de DRM no lado do cliente e sem deixar rastros além da telemetria normal de reprodução.

Os arquivos de saída são containers MPEG-4 Audio válidos (.mp4a / .m4a), diretamente reproduzíveis em qualquer player de mídia compatível com padrões.

**Escopo do impacto:**

- Trilhas de áudio completas de qualquer título Netflix acessível à conta autenticada
- Qualidade de áudio correspondente à qualidade de stream selecionada pelo player adaptativo da Netflix
- Sem rastros nos logs de atividade da conta Netflix além da telemetria normal de reprodução
- Requer acesso local à máquina e uma sessão Netflix autenticada (modelo de ameaça interna)
- URLs de segmento CDN interceptadas são reutilizáveis por qualquer processo sem re-autenticação

---

## Reprodução do PoC

### Passo 1: Iniciar o Chrome com CDP

Execute `START.bat` ou rode a partir de um terminal:

```powershell
powershell -ExecutionPolicy Bypass -File .\launch.ps1
```

O script executa automaticamente:

1. Encerra quaisquer instâncias existentes do Chrome.
2. Inicia o Chrome via flag de sessão interativa do Agendador de Tarefas do Windows (`/it`) para garantir que a janela do navegador apareça na área de trabalho interativa.
3. Sonda `http://127.0.0.1:9222/json/version` até que o endpoint CDP esteja pronto.
4. Aguarda o operador autenticar no Netflix.
5. Aceita URLs de reprodução Netflix da entrada padrão em loop e invoca `narr.exe` para cada uma.

### Passo 2: Autenticar

Faça login no Netflix na janela do Chrome que abrir. Nenhuma credencial é transmitida ou armazenada pelo conjunto de ferramentas do PoC.

### Passo 3: Fornecer a URL Alvo

Cole uma URL de reprodução Netflix quando solicitado:

```
https://www.netflix.com/watch/<videoId>?trackId=<trackId>
```

### Passo 4: Observar a Saída

Os arquivos de áudio são escritos no diretório `downloads\` com a convenção de nomenclatura:

```
<videoId>-<trackId>-<aleatório>.aac.mp4a
```

Renomeie a extensão `.mp4a` para `.m4a` para reprodução em players de mídia padrão.

---

## Notas Técnicas sobre a Arquitetura DRM

O Netflix implementa o Widevine em dois níveis dependendo do dispositivo cliente:

| Nível | TEE de Hardware | Proteção de Vídeo | Proteção de Áudio |
|---|---|---|---|
| L1 | Obrigatório | AES-CBC CENC, descriptografia em TEE | Passagem em texto claro |
| L3 | Apenas software | AES-CBC CENC, CDM por software | Passagem em texto claro |

Em ambas as configurações, a trilha de áudio é entregue sem criptografia CENC, consistente com o comportamento observado neste PoC em múltiplos títulos e idiomas.

Isso não é uma falha de implementação do Widevine. O Widevine criptografa corretamente o que a Netflix instrui que seja criptografado. A lacuna está na política de proteção de conteúdo da Netflix: as trilhas de áudio não são marcadas para criptografia no descritor `ContentProtection` do manifesto DASH para o conjunto de adaptação de áudio.

---

## Cronograma de Divulgação

| Data | Evento |
|---|---|
| 2026-09-16 | Vulnerabilidade identificada durante pesquisa de segurança independente |
| 2026-09-16 | PoC desenvolvido e validado contra a plataforma Netflix em produção |
| 2026-09-16 | Lançamento público do PoC com notificação simultânea ao fornecedor |
| Pendente | Atribuição de identificador CVE pelo MITRE |
| Pendente | Correção pelo fornecedor ou resposta oficial |

---

## Recomendações de Correção

1. Aplicar criptografia CENC aos conjuntos de adaptação de áudio no manifesto DASH, usando o mesmo sistema de chaves Widevine (`com.widevine.alpha`) já utilizado para vídeo.
2. Impor descriptografia baseada em EME para trilhas de áudio no player do navegador, consistente com o tratamento de trilhas de vídeo.
3. Implementar assinatura de requisição no lado do servidor ou vinculação de token de curta duração nas URLs de mídia CDN para impedir a re-busca independente de URLs de segmento interceptadas.
4. Auditar políticas de exposição do CDP: considerar restringir ou detectar conexão inesperada ao CDP de processos Chrome executando sessões de streaming autenticadas.

---

## Referências

- Especificação do Chrome DevTools Protocol: https://chromedevtools.github.io/devtools-protocol/
- Padrão MPEG-DASH: ISO/IEC 23009-1
- Widevine DRM: https://widevine.com
- Especificação W3C Encrypted Media Extensions: https://www.w3.org/TR/encrypted-media/
- Especificação CVSS v3.1: https://www.first.org/cvss/v3-1/
- Especificação CVSS v4.0: https://www.first.org/cvss/v4-0/
- CWE-311: https://cwe.mitre.org/data/definitions/311.html
- CWE-693: https://cwe.mitre.org/data/definitions/693.html
- Repositório do PoC: https://github.com/azurejoga/nav
- Ferramenta upstream original (narr): https://github.com/IljaN/narr
- Vídeo explicativo (Português): https://www.youtube.com/@ohackercego
- Juan Mathews Rebello Santos: http://juanmathewsrebellosantos.com/

---

## Aviso Legal

Esta pesquisa foi conduzida para fins informativos e educacionais sob os princípios de divulgação responsável. O conjunto de ferramentas do PoC é fornecido como evidência técnica da vulnerabilidade descrita. O uso contra qualquer sistema sem autorização explícita é proibido.
