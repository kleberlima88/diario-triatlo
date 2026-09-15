from flask import Flask, render_template, request, flash, redirect, session
from werkzeug.utils import secure_filename
from functools import wraps
import os
import json
import csv
import html
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")

try:
    from openai import OpenAI
    HAS_OPENAI = True
    client = OpenAI(
        api_key=DEEPSEEK_API_KEY,
        base_url="https://api.deepseek.com"
    )
except Exception:
    OpenAI = None
    HAS_OPENAI = False
    client = None

try:
    import pandas as pd
    HAS_PANDAS = True
except Exception:
    pd = None
    HAS_PANDAS = False

app = Flask(__name__)
app.secret_key = "chave_super_secreta_projeto_uncisal" 

# --- CINTURÃO DE SEGURANÇA (OWASP TOP 10) ---
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 
app.config['SESSION_COOKIE_HTTPONLY'] = True   # Previne extração de cookie de sessão via XSS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Proteção de sessão contra CSRF
ALLOWED_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = 'uploads'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

ARQUIVO_USUARIO = 'dados_usuario.json'

def carregar_dados_usuario():
    if os.path.exists(ARQUIVO_USUARIO):
        with open(ARQUIVO_USUARIO, 'r') as f:
            return json.load(f)
    return {"ultimo_teste_cooper": None, "historico_vam": []}

# --- MITIGAÇÃO OWASP: Rate Limiting & Proteção contra Força Bruta (A07:2021) ---
# Armazena em memória as tentativas de login por IP
TENTATIVAS_FALHAS = {}
MAX_TENTATIVAS = 4
TEMPO_BLOQUEIO_SEGUNDOS = 300  # Bloqueio temporário de 5 minutos

def obter_ip_cliente():
    """Recupera o IP real da requisição (com suporte a proxy reverso/Nginx)."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

def verificar_bloqueio_ip(ip):
    """Verifica se o IP está em período de bloqueio temporário."""
    registro = TENTATIVAS_FALHAS.get(ip)
    if not registro:
        return False, 0
    bloqueado_ate = registro.get('bloqueado_ate')
    if bloqueado_ate:
        segundos = (bloqueado_ate - datetime.now()).total_seconds()
        if segundos > 0:
            return True, int(segundos)
        # Tempo expirou: remove bloqueio
        TENTATIVAS_FALHAS.pop(ip, None)
    return False, 0

def registrar_falha_login(ip):
    """Registra tentativa falha e ativa o bloqueio se atingir o limite."""
    agora = datetime.now()
    if ip not in TENTATIVAS_FALHAS:
        TENTATIVAS_FALHAS[ip] = {'tentativas': 1, 'bloqueado_ate': None}
    else:
        TENTATIVAS_FALHAS[ip]['tentativas'] += 1

    tentativas = TENTATIVAS_FALHAS[ip]['tentativas']
    if tentativas >= MAX_TENTATIVAS:
        TENTATIVAS_FALHAS[ip]['bloqueado_ate'] = agora + timedelta(seconds=TEMPO_BLOQUEIO_SEGUNDOS)
        return True, TEMPO_BLOQUEIO_SEGUNDOS
    return False, MAX_TENTATIVAS - tentativas

def resetar_falhas_login(ip):
    """Reseta as tentativas falhas após sucesso na autenticação."""
    TENTATIVAS_FALHAS.pop(ip, None)

# --- MITIGAÇÃO OWASP: Broken Access Control (A01:2021) - Secure by Design ---
# Bloqueio global via before_request (Princípio do Default Deny)
@app.before_request
def bloquear_rotas_internas():
    # Rotas públicas que não requerem autenticação
    rotas_publicas = {'/login', '/favicon.ico'}
    if request.path in rotas_publicas or request.path.startswith('/static'):
        return None

    # Bloqueia qualquer acesso às rotas internas se não houver sessão ativa
    if not session.get('logado'):
        flash('Acesso negado. Por favor, faça login para acessar o painel.', 'error')
        return redirect('/login')

# Decorador mantido como segunda camada de defesa (Defense in Depth)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logado'):
            flash('Acesso negado. Por favor, faça login para acessar o painel.', 'error')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# --- ROTAS DE AUTENTICAÇÃO (EIXO 3) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Se já autenticado, redireciona para a tela principal
    if session.get('logado'):
        return redirect('/')

    ip = obter_ip_cliente()

    if request.method == 'POST':
        # 1. Mitigação OWASP: Rate Limiting / Proteção contra Brute-Force
        bloqueado, tempo_restante = verificar_bloqueio_ip(ip)
        if bloqueado:
            minutos = max(1, tempo_restante // 60)
            flash(
                f'Segurança OWASP: IP temporariamente bloqueado por excesso de tentativas. Aguarde {tempo_restante}s (~{minutos} min).',
                'error'
            )
            return render_template('login.html'), 429

        usuario = request.form.get('usuario', '').strip()
        senha = request.form.get('senha', '')

        # 2. Mitigação OWASP (A07:2021): Credenciais fixas e proteção de sessão
        if usuario == 'admin' and senha == 'triatlo2026':
            resetar_falhas_login(ip)
            session.clear()  # Previne Session Fixation
            session['logado'] = True
            session['usuario'] = 'admin'
            flash('Login realizado com sucesso.', 'success')
            return redirect('/')
        else:
            bloqueou_agora, info = registrar_falha_login(ip)
            if bloqueou_agora:
                flash(
                    'Bloqueio de Segurança OWASP: 4 tentativas incorretas atingidas. Seu IP foi bloqueado temporariamente por 5 minutos.',
                    'error'
                )
                return render_template('login.html'), 429
            else:
                flash(
                    f'Credenciais inválidas. Você possui mais {info} tentativa(s) antes do bloqueio temporário.',
                    'error'
                )

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu do sistema com sucesso.', 'success')
    return redirect('/login')

# --- ROTAS PROTEGIDAS ---
@app.route('/')
@login_required # Proteção ativada
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
            mensagem_status = f"Fim do Macrociclo! Já se passaram {dias_passados} dias. É hora de recalibrar seu pace."
        else:
            mensagem_status = f"Macrociclo ativo. Faltam {90 - dias_passados} dias para a sua próxima reavaliação."

    return render_template('painel.html', precisa_novo_teste=precisa_novo_teste, mensagem_status=mensagem_status)

@app.route('/upload', methods=['POST'])
@login_required # Proteção ativada
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
        
        try:
            if HAS_PANDAS and pd is not None:
                df = pd.read_csv(caminho_salvo)
                distancia_total = df['Distância'].sum() if 'Distância' in df.columns else "8.00"
                fc_maxima = df['FC Máxima'].max() if 'FC Máxima' in df.columns else "187"
                fc_media = df['FC Média'].mean() if 'FC Média' in df.columns else "175"
                tabela_html = df.head().to_html(classes='tabela-garmin', escape=True)
            else:
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
            
            prompt_ia = f"""
Atue como um treinador especialista em periodização de triatlo e corrida.
O atleta submeteu os seguintes dados executados:
- Distância: {distancia_total} km
- Frequência Cardíaca Máxima: {fc_maxima} bpm
- Frequência Cardíaca Média: {fc_media} bpm

Analise o cumprimento das zonas de intensidade:
Regra 1: Se os batimentos indicarem fadiga excessiva, sugira um microciclo regenerativo mantendo o esforço estritamente na Zona Z2.
Regra 2: Se o volume e os paces nas zonas Z2 e Z4 foram cumpridos com eficiência, aplique sobrecarga progressiva e aumente o volume do próximo longão em 10%.
Gere a nova planilha da semana.
"""

            # Conexão com a API do DeepSeek usando a biblioteca openai (modelo 'deepseek-chat')
            analise_ia = None
            try:
                if HAS_OPENAI and client is not None:
                    resposta = client.chat.completions.create(
                        model="deepseek-chat",
                        messages=[
                            {"role": "user", "content": prompt_ia}
                        ]
                    )
                    analise_ia = resposta.choices[0].message.content
                else:
                    import urllib.request
                    req = urllib.request.Request(
                        "https://api.deepseek.com/chat/completions",
                        headers={
                            "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                            "Content-Type": "application/json"
                        },
                        data=json.dumps({
                            "model": "deepseek-chat",
                            "messages": [{"role": "user", "content": prompt_ia}]
                        }).encode("utf-8")
                    )
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        dados_resp = json.loads(resp.read().decode("utf-8"))
                        analise_ia = dados_resp["choices"][0]["message"]["content"]
            except Exception as e_ia:
                flash(f'Aviso da API DeepSeek: {str(e_ia)}', 'error')

            return render_template('analise.html', prompt=prompt_ia, resposta=analise_ia, tabela=tabela_html)
            
        except Exception as e:
            flash(f'Erro ao processar os dados da planilha: {str(e)}', 'error')
            return redirect('/')
            
    else:
        flash('Bloqueio de Segurança: Apenas arquivos .csv são permitidos.', 'error')
        return redirect('/')

if __name__ == '__main__':
    # Mitigação OWASP (Security Misconfiguration): debug desativado para produção
    app.run(debug=False)