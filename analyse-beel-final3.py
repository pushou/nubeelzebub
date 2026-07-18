# analyse-beel-final3.py
"""
Script d'analyse des logs Beelzebub avec UMAP.
Il reproduit les étapes principales du notebook "main-beelzebub-ai-ornith2-final.ipynb"
et ajoute une réduction de dimension UMAP pour visualiser les patterns d'IP.
"""

from pathlib import Path
import gzip
import json
import sys
import logging

import polars as pl
import numpy as np
from sklearn.preprocessing import StandardScaler
import umap
import matplotlib.pyplot as plt

# ---------------------------------------------------------------------------
# Configuration des répertoires (identique à la cellule `cell-2` du notebook)
# ---------------------------------------------------------------------------
LOGDIR = Path("log")
JSONDIR = Path("json")
LOGDIR.mkdir(parents=True, exist_ok=True)
JSONDIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Helper – charger un fichier .gz contenant du NDJSON (une ligne JSON par entrée)
# ---------------------------------------------------------------------------
def load_gz_ndjson(path: Path) -> pl.DataFrame:
    """Charge un fichier .gz NDJSON en un DataFrame Polars.

    Args:
        path: chemin vers le fichier .gz
    Returns:
        pl.DataFrame contenant les enregistrements JSON décodés.
    """
    records = []
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    # ignorer les lignes malformées
                    continue
    except Exception as e:
        logging.error(f"Erreur lors de la lecture de {path}: {e}")
        return pl.DataFrame()
    return pl.DataFrame(records) if records else pl.DataFrame()

# ---------------------------------------------------------------------------
# Chargement de tous les logs présents dans LOGDIR
# ---------------------------------------------------------------------------
def numeric_sort_key(path: Path) -> int:
    """Tri numérique basé sur le suffixe du nom de fichier.
    Exemple : beelzebub.json.123.gz → 123
    """
    try:
        return int(path.stem.split(".")[-1])
    except (ValueError, IndexError):
        return 0

def load_all_logs() -> pl.DataFrame:
    filelist = sorted(LOGDIR.glob("beelzebub.json.*.gz"), key=numeric_sort_key)
    if not filelist:
        logging.error(f"Aucun fichier log trouvé dans {LOGDIR}")
        return pl.DataFrame()
    # Collecter les enregistrements de tous les fichiers en listes de dicts
    all_rows = []
    for p in filelist:
        logging.info(f"Chargement {p.name}")
        df = load_gz_ndjson(p)
        if not df.is_empty():
            # Convertir chaque DataFrame en dictionnaires et les ajouter à la liste globale
            all_rows.extend(df.to_dicts())
    if not all_rows:
        return pl.DataFrame()
    # Créer un DataFrame unique à partir de tous les dictionnaires, ce qui aligne automatiquement les colonnes
    df_all = pl.DataFrame(all_rows)
    # Si la colonne "event" existe et est un struct, on la développe
    if "event" in df_all.columns and isinstance(df_all.schema.get("event"), pl.Struct):
        df_all = df_all.unnest("event")
    return df_all

# ---------------------------------------------------------------------------
# Extraction des features par IP (SSH et HTTP) – similaire aux cellules du notebook
# ---------------------------------------------------------------------------
def extract_features(df_all: pl.DataFrame):
    # Séparer les protocoles
    dfssh = (
        df_all.filter(pl.col("Protocol") == "SSH")
        .select([
            "DateTime",
            "RemoteAddr",
            "Protocol",
            "SourceIp",
            "Command",
            "Password",
        ])
        if not df_all.is_empty()
        else pl.DataFrame()
    )
    dfhttp = (
        df_all.filter(pl.col("Protocol") == "HTTP")
        .select([
            "DateTime",
            "RemoteAddr",
            "Protocol",
            "SourceIp",
            "Headers",
            "Cookies",
            "UserAgent",
            "HostHTTPRequest",
            "Body",
            "HTTPMethod",
            "RequestURI",
            "TLSServerName",
        ])
        if not df_all.is_empty()
        else pl.DataFrame()
    )

    # Comptage par IP
    ssh_by_ip = (
        dfssh.group_by("SourceIp").agg(pl.col("SourceIp").len().alias("ssh_attempts"))
        if not dfssh.is_empty()
        else pl.DataFrame(schema={"SourceIp": str, "ssh_attempts": int})
    )
    http_by_ip = (
        dfhttp.group_by("SourceIp").agg(pl.col("SourceIp").len().alias("http_requests"))
        if not dfhttp.is_empty()
        else pl.DataFrame(schema={"SourceIp": str, "http_requests": int})
    )

    # Jointure des deux tables
    features = ssh_by_ip.join(http_by_ip, on="SourceIp", how="left").fill_null(0)
    # Ratio SSH/HTTP (ajout d'une petite constante pour éviter la division par zéro)
    features = features.with_columns(
        ((pl.col("ssh_attempts") / (pl.col("http_requests") + 1)).alias("ssh_http_ratio"))
    )
    return features

# ---------------------------------------------------------------------------
# Application d'UMAP sur les features
# ---------------------------------------------------------------------------
def run_umap(features: pl.DataFrame, n_neighbors: int = 15, min_dist: float = 0.1):
    # Sélectionner les colonnes numériques
    numeric_cols = [c for c, t in features.schema.items() if t in (pl.Int64, pl.Int32, pl.UInt64, pl.UInt32, pl.Float64, pl.Float32)]
    if not numeric_cols:
        logging.error("Aucune colonne numérique disponible pour UMAP")
        return None
    data = features.select(numeric_cols).to_numpy()
    # Normalisation
    scaler = StandardScaler()
    data_norm = scaler.fit_transform(data)
    # UMAP
    reducer = umap.UMAP(n_neighbors=n_neighbors, min_dist=min_dist, n_components=2, random_state=42)
    embedding = reducer.fit_transform(data_norm)
    # Retour sous forme de DataFrame Polars enrichi
    umap_df = pl.DataFrame({
        "UMAP1": embedding[:, 0],
        "UMAP2": embedding[:, 1],
        "SourceIp": features["SourceIp"],
        "ssh_attempts": features["ssh_attempts"],
        "http_requests": features["http_requests"],
        "ssh_http_ratio": features["ssh_http_ratio"],
    })
    return umap_df

# ---------------------------------------------------------------------------
# Visualisation simple (scatter) et sauvegarde CSV
# ---------------------------------------------------------------------------
def plot_and_save(umap_df: pl.DataFrame, out_png: Path = Path("umap_plot.png"), out_csv: Path = Path("umap_results.csv")):
    plt.figure(figsize=(10, 8))
    plt.scatter(umap_df["UMAP1"], umap_df["UMAP2"], c="steelblue", edgecolor="k", alpha=0.7)
    plt.title("UMAP – Beelzebub logs (SSH/HTTP per IP)")
    plt.xlabel("UMAP1")
    plt.ylabel("UMAP2")
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()
    # Export CSV pour usage ultérieur
    umap_df.write_csv(out_csv)
    logging.info(f"Résultats UMAP écrits dans {out_csv} et graphique sauvegardé sous {out_png}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    df_all = load_all_logs()
    if df_all.is_empty():
        logging.error("Aucun log chargé – interrompre le script.")
        sys.exit(1)

    features = extract_features(df_all)
    if features.is_empty():
        logging.error("Aucun feature trouvé – interrompre le script.")
        sys.exit(1)

    umap_df = run_umap(features)
    if umap_df is None:
        logging.error("UMAP a échoué.")
        sys.exit(1)

    plot_and_save(umap_df)

if __name__ == "__main__":
    main()
