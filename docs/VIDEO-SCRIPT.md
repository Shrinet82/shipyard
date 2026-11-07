# Demo video: narration script

About 3 minutes. Read at a calm pace; each block is one scene, and the time is where it starts. Pauses between blocks are fine: the video is cut to your voice.

| # | Starts | On screen | Say |
|---|---|---|---|
| 1 | 0:00 | Title: Shipyard | "This is Shipyard: a chat room that ships software, and can't be talked into doing anything it shouldn't." |
| 2 | 0:08 | Five tools pour into one chat room | "Small teams run their work in chat, and their infrastructure in five other places. Shipyard brings deploys, pull requests, alerts and tickets into the chat room you already use. The hard part is making that safe." |
| 3 | 0:22 | The architecture draws itself | "It is built on Switch. Switch carries the messages, and it tells us exactly who sent each one. In front of everything sits the Gatekeeper, a custom Switch agent. It is the only part that holds credentials. The AI agents sit in the rooms like colleagues, but all they can do is ask." |
| 4 | 0:42 | Mattermost: four teammates | "Here is a team of four. Anya is the owner, Rahul a maintainer, Meera a deployer and Dev a viewer. Dev asks for a restart: denied. Meera scales the app: done. Meera tries to run a command inside a pod: denied. Rahul can, and it runs. The role decides, not the wording." |
| 5 | 1:02 | A ticket from one sentence | "Planning happens in the same room. Anya types one sentence, and the Repo Agent creates the ticket and tells Rahul. A pull request that says 'Fixes SY-6' links itself and moves the ticket to review. Nobody drags a card." |
| 6 | 1:20 | Meera's desk room | "Every person gets a private desk room with a briefing: their tickets, what changed, and the first step to take." |
| 7 | 1:30 | Merge with approval, then GitHub | "Rahul asks to merge. A merge needs a second person. Meera can't approve it. Anya does, and the GitHub App merges exactly the commit that was approved." |
| 8 | 1:50 | The gate flow, then the blocked report | "Every CI run produces a software bill of materials and a vulnerability scan. A pull request that brings in a new critical vulnerability is blocked, and only an owner can override it, for that exact commit." |
| 9 | 2:08 | An alert from SigNoz | "When something breaks, the first thing that arrives is evidence. SigNoz fires an alert. Shipyard opens an incident and a ticket, posts the real log lines with secrets removed, and the Ops Agent writes a three-line diagnosis. It can't change anything. People decide." |
| 10 | 2:30 | The dashboard | "The dashboard shows the board, every security report, and an audit log that is hash-chained, so an edited row breaks the chain. It has no approve button, on purpose." |
| 11 | 2:42 | The installer | "Installing it is one command. A guided installer does the machine work and stops only for what a person has to do: sign in, press two buttons for the GitHub App, and say who you are." |
| 12 | 2:55 | Closing card | "Shipyard. Built on Switch. The code is on GitHub." |

Recording tips: a quiet room, the phone 20 cm from your mouth, one take per block is fine. Send the file (mp3, m4a or wav); I cut the scenes to your timing and mix the music under it.
