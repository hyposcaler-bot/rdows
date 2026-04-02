use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, Json};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

use crate::kv::{KvError, KvStore, MR_SIZE, SLOT_COUNT, SLOT_SIZE};

pub type SharedKvStore = Arc<Mutex<KvStore>>;

pub fn router(store: SharedKvStore) -> Router {
    Router::new()
        .route("/", get(index_html))
        .route("/api/kv/:key", get(get_key).put(put_key).delete(delete_key))
        .route("/api/slots", get(get_slots))
        .route("/api/stats", get(get_stats))
        .layer(CorsLayer::permissive())
        .with_state(store)
}

async fn index_html() -> Html<&'static str> {
    Html(include_str!("ui.html"))
}

#[derive(Deserialize)]
struct PutBody {
    value: String,
}

async fn put_key(
    State(store): State<SharedKvStore>,
    Path(key): Path<String>,
    Json(body): Json<PutBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut kv = store.lock().await;
    match kv.put(&key, &body.value).await {
        Ok(result) => Ok(Json(serde_json::to_value(result).unwrap())),
        Err(KvError::TableFull) => Err((
            StatusCode::INSUFFICIENT_STORAGE,
            Json(json!({"error": "hash table full"})),
        )),
        Err(KvError::KeyTooLong) => Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error": "key too long (max 255 bytes)"})),
        )),
        Err(KvError::ValueTooLong) => Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error": "value too long (max 764 bytes)"})),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )),
    }
}

async fn get_key(
    State(store): State<SharedKvStore>,
    Path(key): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut kv = store.lock().await;
    match kv.get(&key).await {
        Ok(Some(result)) => Ok(Json(serde_json::to_value(result).unwrap())),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "key not found", "key": key})),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )),
    }
}

async fn delete_key(
    State(store): State<SharedKvStore>,
    Path(key): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut kv = store.lock().await;
    match kv.delete(&key).await {
        Ok(result) => {
            let status = if result.found {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            };
            if result.found {
                Ok(Json(serde_json::to_value(result).unwrap()))
            } else {
                Err((status, Json(json!({"error": "key not found", "key": key}))))
            }
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )),
    }
}

async fn get_slots(
    State(store): State<SharedKvStore>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut kv = store.lock().await;
    match kv.dump_slots().await {
        Ok(slots) => Ok(Json(serde_json::to_value(slots).unwrap())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )),
    }
}

async fn get_stats(State(store): State<SharedKvStore>) -> Json<Value> {
    let kv = store.lock().await;
    Json(json!({
        "session_id": format!("0x{:08X}", kv.session_id),
        "rkey": format!("0x{:08X}", kv.remote_rkey_value),
        "mr_size": MR_SIZE,
        "slot_count": SLOT_COUNT,
        "slot_size": SLOT_SIZE,
    }))
}
