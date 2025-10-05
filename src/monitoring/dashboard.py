"""Real-time Dashboard"""

import logging
from dash import Dash, html, dcc
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output
import plotly.graph_objs as go
import asyncio

logger = logging.getLogger(__name__)


async def start_dashboard():
    """
    Start the real-time monitoring dashboard
    
    This creates a beautiful web-based dashboard showing:
    - Real-time threat detection
    - Traffic statistics
    - ML model performance
    - Attack heatmaps
    - Incident timeline
    """
    
    try:
        # Create Dash app
        app = Dash(
            __name__,
            external_stylesheets=[dbc.themes.CYBORG],
            title="AI-NGFW Dashboard"
        )
        
        # Dashboard layout
        app.layout = dbc.Container([
            dbc.Row([
                dbc.Col([
                    html.H1("🛡️ AI-Driven Next-Generation Firewall", className="text-center mb-4"),
                    html.P("Real-time Threat Detection & Zero Trust Monitoring", className="text-center text-muted")
                ])
            ]),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Total Requests", className="card-title"),
                            html.H2(id="total-requests", children="0", className="text-success")
                        ])
                    ])
                ], width=3),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Blocked", className="card-title"),
                            html.H2(id="blocked-requests", children="0", className="text-danger")
                        ])
                    ])
                ], width=3),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Block Rate", className="card-title"),
                            html.H2(id="block-rate", children="0%", className="text-warning")
                        ])
                    ])
                ], width=3),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Uptime", className="card-title"),
                            html.H2(id="uptime", children="0s", className="text-info")
                        ])
                    ])
                ], width=3),
            ], className="mb-4"),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Threats by Type", className="card-title"),
                            dcc.Graph(id="threats-chart")
                        ])
                    ])
                ], width=6),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Threats by Severity", className="card-title"),
                            dcc.Graph(id="severity-chart")
                        ])
                    ])
                ], width=6),
            ], className="mb-4"),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Recent Incidents", className="card-title"),
                            html.Div(id="incidents-list")
                        ])
                    ])
                ])
            ]),
            
            # Auto-refresh interval
            dcc.Interval(
                id='interval-component',
                interval=5*1000,  # Update every 5 seconds
                n_intervals=0
            )
        ], fluid=True, className="p-4")
        
        @app.callback(
            [
                Output('total-requests', 'children'),
                Output('blocked-requests', 'children'),
                Output('block-rate', 'children'),
                Output('uptime', 'children'),
                Output('threats-chart', 'figure'),
                Output('severity-chart', 'figure'),
                Output('incidents-list', 'children')
            ],
            [Input('interval-component', 'n_intervals')]
        )
        def update_dashboard(n):
            """Update dashboard with latest metrics"""
            
            # Mock data for demonstration
            import random
            
            total = 1000 + n * 10
            blocked = int(total * 0.15)
            block_rate = f"{(blocked/total*100):.1f}%"
            uptime = f"{n*5}s"
            
            # Threats by type chart
            threat_types = ['SQL Injection', 'XSS', 'Cmd Injection', 'Path Traversal', 'Anomaly']
            threat_counts = [random.randint(10, 100) for _ in threat_types]
            
            threats_fig = go.Figure(data=[
                go.Bar(x=threat_types, y=threat_counts, marker_color='indianred')
            ])
            threats_fig.update_layout(
                template='plotly_dark',
                height=300,
                margin=dict(l=20, r=20, t=20, b=20)
            )
            
            # Severity chart
            severities = ['Critical', 'High', 'Medium', 'Low']
            severity_counts = [random.randint(5, 50) for _ in severities]
            
            severity_fig = go.Figure(data=[
                go.Pie(
                    labels=severities,
                    values=severity_counts,
                    marker=dict(colors=['#d62728', '#ff7f0e', '#ffbb78', '#98df8a'])
                )
            ])
            severity_fig.update_layout(
                template='plotly_dark',
                height=300,
                margin=dict(l=20, r=20, t=20, b=20)
            )
            
            # Recent incidents
            incidents = []
            for i in range(5):
                incidents.append(
                    dbc.Alert([
                        html.Strong(f"Incident #{1000+i}: "),
                        f"SQL Injection from 192.0.2.{i+1} - Blocked"
                    ], color="danger", className="mb-2")
                )
            
            return total, blocked, block_rate, uptime, threats_fig, severity_fig, incidents
        
        logger.info("Starting dashboard on port 8050...")
        
        # Run dashboard in a separate thread
        import threading
        def run_dashboard():
            app.run_server(host='0.0.0.0', port=8050, debug=False)
        
        dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
        dashboard_thread.start()
        
        logger.info("✅ Dashboard started at http://localhost:8050")
        
    except Exception as e:
        logger.error(f"Error starting dashboard: {e}", exc_info=True)
