use axum::{
    routing::get,
    Router
};
use serde::Serialize;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use utoipa::{OpenApi, ToSchema};


use crate::web::woo::*;
use crate::web::waa::*;

#[derive(OpenApi)]
#[openapi(
    paths(
        json_handler,
        html_handler
    ),
    components(schemas(Info))
)]
struct ApiDoc;

#[derive(Clone)]
struct AppState {
    config: std::sync::Arc<crate::Configuration>,
    state: std::sync::Arc<crate::State>,
}


pub(crate) async fn run(state:std::sync::Arc<crate::State>,config:std::sync::Arc<crate::Configuration>) {

    let port = config.web_ui_port.unwrap_or(8080);

    let mut oa = ApiDoc::openapi();
    oa.info.title = "GELF-LB".into();
    oa.info.version = "0.0.1".into();

    let app = Router::new()
        .merge(
            utoipa_swagger_ui::SwaggerUi::new("/api-docs").url("/api-docs/openapi.json", oa)
        )
        .route("/json", get(woo::json_handler))
        .route("/html", get(waa::html_handler))
        .route("/", get(waa::html_handler))
        .with_state(AppState {
            config: config,
            state: state
        })  
        ;
       
    let address = SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port));
    let listener = TcpListener::bind(&address).await.unwrap();
    log::info!("web-ui started at {address:?}");
    axum::serve(listener, app.into_make_service()).await.unwrap();
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
mod waa {
    #[utoipa::path(
        get,
        tag = "UI",
        path = "/html",
        params(),
        responses(
            (status = 200, description = "serves the web ui")
        )
    )]
    pub async fn html_handler(
        state: axum::extract::State<super::AppState>,
    ) -> impl axum::response::IntoResponse {
        
        let cfg: &crate::Configuration = &state.config.as_ref();
        let cfg_json = format!("<br/><b>Configuration:</b><br/><pre>{}</pre>",&toml::to_string(&cfg).unwrap());
        let notes = "<br/><p class='faded'> * total forwarded messages will typically be lower than the udp count due to invalid incoming data and the fact that a single message can consist of multiple udp packets (chunked mode)</p>";

        let make_row = |k:&str,v:&str| format!("<tr><td>{k}</td><td>{v}</td></tr>");
        let rows = [
            make_row("total seen incoming udp packets",&state.state.nr_of_handled_udp_packets.read().unwrap().to_string()),
            make_row("* total forwarded messages",&state.state.nr_of_forwarded_messages.read().unwrap().to_string())
        ].join("\n");
        let html = include_str!("../ui.html")
            .replace("$title","GELF-LB UI")
            .replace("$header","GELF-LB")
            .replace("$rows",&rows)
            .replace("$notes",&notes)
            .replace("$configuration",&cfg_json)
            .replace("$app_version",&super::VERSION);
        axum::response::Html(html)
    }
}


#[derive(Serialize, ToSchema)]
struct Info {
    nr_of_forwarded_messages : u64,
    nr_of_handled_udp_packets : u64
}

mod woo {
    use super::Info;
    #[utoipa::path(
        get,
        tag = "DATA",
        path = "/json",
        params(),
        responses(
            (status = 200, description = "current application state")
        )
    )]
    pub async fn json_handler(state: axum::extract::State<super::AppState>,) -> axum::Json<Info> {
       axum::Json(Info {
            nr_of_forwarded_messages : *state.state.nr_of_forwarded_messages.read().unwrap(),
            nr_of_handled_udp_packets : *state.state.nr_of_handled_udp_packets.read().unwrap()
        })
    }
}