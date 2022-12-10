use poem_openapi::{
    types::{ParseFromJSON, ToJSON},
    Object,
};
use serde::{Deserialize, Serialize};

#[derive(Object, Deserialize, Serialize)]
pub struct ApiError<T: ParseFromJSON + ToJSON + Send + Sync> {
    msg: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<T>,
}
