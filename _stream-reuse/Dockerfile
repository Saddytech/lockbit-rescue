FROM i386/debian:latest

# Installa le dipendenze necessarie per compilare
RUN apt-get update && apt-get install -y \
    build-essential \
    make \
    gcc-multilib \
    && rm -rf /var/lib/apt/lists/*

# Crea una cartella di lavoro esplicita
WORKDIR /app

# Copia TUTTO il contenuto della cartella locale corrente (quella dove risiede il Makefile) 
# nella cartella /app del container
COPY . .

# Verifica che i file siano stati copiati (opzionale, utile per debug)
RUN ls -la

# Compila
RUN make
