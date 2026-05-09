pub trait RequestStage<Request, Response> {
    fn handle(&self, request: Request) -> Response;
}
