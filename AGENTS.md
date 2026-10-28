# Istruzioni per il fork di ricerca FeedConCura

Questo fork è la repository interna di sviluppo di FeedConCura. Le istruzioni di riferimento e il piano sono nella repository esterna:

- https://github.com/il-prof-f-a/tiktok-feed-con-cura/blob/main/AGENTS.md
- https://github.com/il-prof-f-a/tiktok-feed-con-cura/blob/main/docs/technical-workflow.md
- https://github.com/il-prof-f-a/tiktok-feed-con-cura/blob/main/docs/operational-plan.md

Nel workspace con submodule leggerle anche dai file locali `../../AGENTS.md` e `../../docs/technical-workflow.md`, che possono essere più aggiornati del branch remoto.

## Regole obbligatorie

- Sviluppare codice, configurazioni tecniche e test qui; documentazione di progetto e pianificazione vanno nella repo esterna.
- In caso di dubbio chiedere sempre al responsabile prima dell'azione interessata. Non inventare API, metadati o autorizzazioni.
- Usare https://github.com/il-prof-f-a/tiktok-feed-con-cura/issues come backlog. Collegare commit e risultati all'URL completo dell'issue esterna.
- Creare branch `codex/<tema>` e commit in questa repo; pubblicare il branch prima che la repo esterna aggiorni il riferimento del submodule.
- Non abilitare o avviare le pipeline ereditate di build/pubblicazione senza autorizzazione esplicita per quella fase.
- Non introdurre bypass di autenticazione, firma, DRM, integrità o antifrode; non distribuire APK modificati come soluzione per minori.
- Nessun dato reale di minori, token, dump di account o media personali nei commit. Usare fixture sintetiche.
- Prima di cambiare le sorgenti delle patch o la logica di blocco, presentare la decisione nell'issue al responsabile. Il filtro Morphe risiede a monte in una repo distinta: non presumere di poterlo modificare tramite i soli script di build presenti qui.

Il setup iniziale non modifica il comportamento dell'app e non costituisce una validazione delle patch ereditate.
