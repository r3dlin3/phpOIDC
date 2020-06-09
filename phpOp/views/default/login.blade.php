@extends('master')

@section('title')
@_e('TitleLogin')
@endsection

@section('content')
<div class="brand">
    @if (!empty($client['logo_uri']))
    <img src="{!! $client['logo_uri'] !!}" alt="{{ $client['client_name'] }}">
    @else
    <img src="{!! OP_URL !!}/img/logo.png" alt="logo">
    @endif
</div>
<div class="card fat">
    <div class="card-body">
        <h4 class="card-title">@_ef('%s OP Login', $client['client_name'])</h4>
        @if ($enable_social_login && (empty($display_name) || empty($user_id)))
        <div class="container">
            <div class="row">
                <ul class="social-btns mx-auto">
                @foreach ($socialite as $provider=>$enable)
                    @if($enable)
                    <li><a class="btn btn-{!! $provider !!}" href="{!! OP_SOCIALITE_EP !!}{!! $provider !!}">
                        <span class="align-middle">
                            <img alt="@_e($provider)" title="@_ef('Sign in with %s', $this->_e($provider))" class="float-left" src="{!! OP_PATH !!}/img/socialite/{!! $provider !!}.png">    
                            @_ef('Sign in with %s', $this->_e($provider))
                        </a></li>
                    </span>
                    @endif
                @endforeach
                </ul>
            </div>
        </div>
		<div class="row login-or">
			<div class="w-100">
				<hr class="hr-or">
				<span class="span-or">@_e('or')</span>
			</div>
		</div>
        @endif

        @if ($error)
        <div class="alert alert-danger" role="alert">
            @_e('Authentication error')
        </div>
        @endif

        <form method="POST" class="my-login-validation" action="{!! $action_url !!}" novalidate="">
            <div class="form-group">
                <label for="username">@_e('E-Mail Address')</label>
                @if (!empty($display_name) && !empty($user_id))
                <input id="display_name" type="email" class="form-control" name="display_name" value="{{ $display_name  }}" disabled>
                <input id="username" type="hidden" class="form-control" name="username" value="{{ $user_id  }}">
                @else
                <input id="username" type="input" class="form-control" name="username" value="{{ $user_id  }}" required autofocus tabindex="1">
                @endif
                <div class="invalid-feedback">
                    @_e('Email is invalid')
                </div>
            </div>

            <div class="form-group">
                <label for="password">@_e('Password')
                @if ( $site['enable_password_reset'] == true )
                    <a href="{!! $site['password_reset_url'] !!}" class="float-right">
                        @_e('Forgot Password?')
                    </a>
                @endif
                </label>
                <input id="password" type="password" class="form-control" name="password" required data-eye tabindex="2">
                <div class="invalid-feedback">
                    @_e('Password is required')
                </div>
            </div>

            <div class="form-group">
                <div class="custom-checkbox custom-control">
                    <input type="checkbox" name="persist" id="persist" class="custom-control-input" tabindex="3">
                    <label for="persist" class="custom-control-label">@_e('Remember Me')</label>
                </div>
            </div>

            <div class="form-group m-0">
                <button id="login" type="submit" class="btn btn-primary btn-block" tabindex="4">
                    @_e('Login')
                </button>
            </div>
            @if ( $site['enable_registration'] == true )
            <div class="mt-4 text-center">
                @_e("Don't have an account?")
            </div>
            <div class="text-center">
                <a id="register" class="btn btn-outline-primary btn-block mt-2" href="{!! $site['registration_url'] !!}">@_e('Create an account')</a>
            </div>
            @endif
        </form>
    </div>
    @if (!empty($client['policy_uri']) || !empty($client['tos_uri']))
    <div class="card-body">
        @if (!empty($client['policy_uri']))
        <a href="{!! $client['policy_uri'] !!}" class="card-link">@_e('Policy')</a>
        @endif
        @if (!empty($client['tos_uri']))
        <a href="{!! $client['tos_uri'] !!}" class="card-link">@_e('Terms of use')</a>
        @endif
    </div>
    @endif
</div>
@endsection