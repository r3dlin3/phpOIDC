<?php
include_once(__DIR__ . '/../phpOp/config.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Home</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css" integrity="sha384-9aIt2nRpC12Uk9gS9baDl411NQApFmC26EwAOH8WgZl5MYYxFfc+NcPb1dKGj7Sk" crossorigin="anonymous">
</head>
<body class="my-login-page">
    <section class="h-100">
        <div class="container h-100">
            <div class="row justify-content-center h-100">
                <div class="card-wrapper w-50 mt-5 pt-5">
                    <div class="card">
                        <div class="card-body">
                            <a href="phpRp" class="btn btn-primary btn-block">Go to test Relying Party</a>
                            <a href="phpRp/admin/provider" class="btn btn-primary btn-block mt-4">Go to test Relying Party Admin pages</a>
                            <a href=".well-known/openid-configuration" class="btn btn-primary btn-block mt-4">Obtaining OpenID Provider Configuration Information</a>
                            <?php
                                global $config;
                                if ($config['site']['enable_admin']) {
                            ?>
                            <a href="phpOp/admin" class="btn btn-primary btn-block mt-4">Go to test OP Admin pages</a>
                            <?php
                                }
                            ?>
                        </div>
                    </div>
                    <div class="footer">
                        Copyright &copy; 2020 &mdash; Your Company
                    </div>
                </div>
            </div>
        </div>
    </section>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js" integrity="sha384-DfXdz2htPH0lsSSs5nCTpuj/zy4C+OGpamoFVy38MVBnE+IbbVYUew+OrCXaRkfj" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js" integrity="sha384-OgVRvuATP1z7JjHLkuOU7Xw704+h835Lr+6QL9UvYjZE3Ipu6Tp75j7Bh/kR0JKI" crossorigin="anonymous"></script>
</body>
</html>