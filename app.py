from flask import Flask, render_template, request, flash, redirect
from werkzeug.utils import secure_filename
import os
import json
import csv
import html
from datetime import datetime

# Tentativa de importação do Pandas com fallback resiliente para ambientes com Controle de Aplicativo do Windows
try:
    import pandas as pd
    HAS_PANDAS = True
except Exception:
    pd = None
    HAS_PANDAS = False

app = Flask(__name__)
app.secret_key = "chave_super_secreta_projeto_uncisal" # Necessário para exibir mensagens de erro/sucesso na tela

# --- CINTURÃO DE SEGURANÇA (OWASP TOP 10) ---
# 1. Limite de tamanho de arquivo: 2MB (Mitiga ataques de Negação de Serviço)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 
# 2. Extensões permitidas estritas
ALLOWED_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = 'uploads'

# Cria a pasta de uploads se ela não existir
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

ARQUIVO_USUARIO = 'dados_usuario.json'

def carregar_dados_usuario():
    if os.path.exists(ARQUIVO_USUARIO):
        with open(ARQUIVO_USUARIO, 'r') as f:
            return json.load(f)
    return {"ultimo_teste_cooper": None, "historico_vam": []}

@app.route('/')
def painel_treinamento():
    dados = carregar_dados_usuario()
    precisa_novo_teste = False
    mensagem_status = ""

    if not dados["ultimo_teste_cooper"]:
        precisa_novo_teste = True
        mensagem_status = "Bem-vindo à periodização! Para iniciarmos, realize o Teste de Cooper de 12 minutos."
    else:
        data_ultimo_teste = datetime.strptime(dados["ultimo_teste_cooper"], "%Y-%m-%d")
        dias_passados = (datetime.now() - data_ultimo_teste).days
        if dias_passados >= 90:
            precisa_novo_teste = True
            mensagem_status = f"Fim do Macrociclo! Já se passaram {dias_passados} dias. É hora de recalibrar seu pace com um novo Teste de Cooper."
        else:
            mensagem_status = f"Macrociclo ativo. Faltam {90 - dias_passados} dias para a sua próxima reavaliação de pace."

    return render_template('painel.html', precisa_novo_teste=precisa_novo_teste, mensagem_status=mensagem_status)

# --- ROTA DE RECEBIMENTO DO ARQUIVO ---
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('Nenhum arquivo detectado pelo sistema.', 'error')
        return redirect('/')
    
    file = request.files['file']
    
    if file.filename == '':
        flash('Nenhum arquivo foi selecionado.', 'error')
        return redirect('/')
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        caminho_salvo = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(caminho_salvo)
        
        # --- O CÉREBRO DA APLICAÇÃO (Processamento Pandas + Prompt IA) ---
        try:
            if HAS_PANDAS and pd is not None:
                # Lê o arquivo CSV exportado do Garmin via Pandas
                df = pd.read_csv(caminho_salvo)
                
                distancia_total = df['Distância'].sum() if 'Distância' in df.columns else "8.00"
                fc_maxima = df['FC Máxima'].max() if 'FC Máxima' in df.columns else "187"
                fc_media = df['FC Média'].mean() if 'FC Média' in df.columns else "175"
                
                tabela_html = df.head().to_html(classes='tabela-garmin', escape=True)
            else:
                # Fallback nativo resiliente caso a política de segurança do Windows bloqueie DLLs do C/NumPy
                encoding = "utf-8-sig"
                try:
                    with open(caminho_salvo, "r", encoding="utf-8-sig") as f:
                        f.read(1024)
                except UnicodeDecodeError:
                    encoding = "latin-1"

                with open(caminho_salvo, "r", encoding=encoding, newline="") as f:
                    reader = csv.reader(f)
                    rows = list(reader)

                headers = rows[0] if rows else []
                data_rows = rows[1:6] if len(rows) > 1 else []

                headers_lower = [h.strip().lower() for h in headers]
                dist_idx = next((i for i, h in enumerate(headers_lower) if "dist" in h), None)
                fc_max_idx = next((i for i, h in enumerate(headers_lower) if "fc" in h and ("máx" in h or "max" in h)), None)
                fc_med_idx = next((i for i, h in enumerate(headers_lower) if "fc" in h and ("méd" in h or "med" in h)), None)

                def parse_num(val):
                    try:
                        return float(val.strip().replace(",", "."))
                    except (ValueError, AttributeError):
                        return None

                # Cálculo de valores ou padrões simulados
                all_data = rows[1:] if len(rows) > 1 else []
                dists = [parse_num(r[dist_idx]) for r in all_data if dist_idx is not None and dist_idx < len(r)]
                dists = [d for d in dists if d is not None]
                distancia_total = f"{sum(dists):.2f}" if dists else "8.00"

                fc_maxs = [parse_num(r[fc_max_idx]) for r in all_data if fc_max_idx is not None and fc_max_idx < len(r)]
                fc_maxs = [f for f in fc_maxs if f is not None]
                fc_maxima = f"{int(max(fc_maxs))}" if fc_maxs else "187"

                fc_meds = [parse_num(r[fc_med_idx]) for r in all_data if fc_med_idx is not None and fc_med_idx < len(r)]
                fc_meds = [f for f in fc_meds if f is not None]
                fc_media = f"{sum(fc_meds)/len(fc_meds):.1f}" if fc_meds else "175"

                th_html = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
                tb_html = "".join("<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in r) + "</tr>" for r in data_rows)
                tabela_html = f'<table class="tabela-garmin"><thead><tr>{th_html}</tr></thead><tbody>{tb_html}</tbody></table>'
            
            # Montando a instrução fisiológica que será enviada para a API da IA
            prompt_ia = f"""
Atue como um treinador especialista em periodização de triatlo e corrida.
O atleta submeteu os seguintes dados executados:
- Distância: {distancia_total} km
- Frequência Cardíaca Máxima: {fc_maxima} bpm
- Frequência Cardíaca Média: {fc_media} bpm

Analise o cumprimento das zonas de intensidade:
Regra 1: Se os batimentos indicarem fadiga excessiva (comum após noites sem dormir ou desgaste físico extremo), sugira um microciclo regenerativo mantendo o esforço estritamente na Zona Z2.
Regra 2: Se o volume e os paces nas zonas Z2 e Z4 foram cumpridos com eficiência, aplique sobrecarga progressiva e aumente o volume do próximo longão em 10%.
Gere a nova planilha da semana.
"""
            return render_template('analise.html', prompt=prompt_ia, tabela=tabela_html)
            
        except Exception as e:
            flash(f'Erro ao processar os dados da planilha: {str(e)}', 'error')
            return redirect('/')
            
    else:
        flash('Bloqueio de Segurança: Apenas arquivos .csv são permitidos.', 'error')
        return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
