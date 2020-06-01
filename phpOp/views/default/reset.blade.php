@extends('master')

@section('title')
@_e('TitlePasswordReset')
@endsection

@section('content')
<div class="brand">
    <img src="{!! $site['theme_uri'] !!}/img/logo.jpg" alt="logo">
</div>
<div class="card fat">
    <div class="card-body">
        <h4 class="card-title">@_e('Forgot Password')</h4>
        @if ($error)
        <div class="alert alert-danger" role="alert">
        @_e('Could not change password')
        </div>
        @endif

        <form method="POST" class="my-login-validation" action="{!! $action_url !!}" novalidate="">
            <div class="form-group">
                <label for="new-password">@_e('New Password')</label>
                <input id="new-password" type="password" class="form-control" name="password" required autofocus data-eye>
                <div class="invalid-feedback">
                @_e('Password is required')
                </div>
                <div class="form-text text-muted">
                @_e('Make sure your password is strong and easy to remember')
                </div>
            </div>
            <div class="form-group m-0">
                <button type="submit" class="btn btn-primary btn-block" id="register">
                    @_e('Reset Password')
                </button>
            </div>
        </form>
    </div>
</div>
@endsection