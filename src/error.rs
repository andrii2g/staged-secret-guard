use thiserror::Error;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("requested operation is not implemented in the scaffold")]
    NotImplemented,
}
