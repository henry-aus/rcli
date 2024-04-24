use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Html,
    routing::get,
    Router,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on {}", path, addr);

    let state = HttpServeState { path: path.clone() };
    // axum router
    let router = Router::new()
        .nest_service("/tower", ServeDir::new(path))
        .route("/*path", get(file_handler))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> (StatusCode, Html<String>) {
    //println!("Reading path {:?}", path);
    let p = std::path::Path::new(&state.path).join(&path);
    info!("Reading file {:?}", p);
    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            Html::from(format!("File {} note found", p.display())),
        )
    } else if p.is_dir() {
        // if it is a directory, list all files/subdirectories
        // as <li><a href="/path/to/file">file name</a></li>
        // <html><body><ul>...</ul></body></html>
        match list_dir(p).await {
            Ok(files) => {
                let f = |filename| {
                    format!(
                        "<li><a href=\"/{}/{}\">{}</a></li>",
                        path, filename, filename
                    )
                };
                let files = files.iter().map(f).collect::<Vec<String>>().join("");
                let body = format!("<html><body><ul>{}</ul></body></html>", files);
                (StatusCode::OK, Html::from(body))
            }
            Err(e) => {
                warn!("Error reading dir: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Html::from(e.to_string()))
            }
        }
    } else {
        match tokio::fs::read_to_string(p).await {
            Ok(content) => {
                info!("Read {} bytes", content.len());
                (StatusCode::OK, Html::from(content))
            }
            Err(e) => {
                warn!("Error reading file: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Html::from(e.to_string()))
            }
        }
    }
}

async fn list_dir(p: PathBuf) -> Result<Vec<String>> {
    let mut files = Vec::<String>::new();
    let mut read_dir = tokio::fs::read_dir(p).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        if let Ok(filename) = entry.file_name().into_string() {
            files.push(filename);
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let (status, _) = file_handler(State(state), Path("Cargo.toml".to_string())).await;
        assert_eq!(status, StatusCode::OK);
        //assert!(content.trim().starts_with("[package]"));
    }
}
