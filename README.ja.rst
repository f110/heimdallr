===================
heimdallr
===================

ゼロトラストネットワークに基づいた認証プロキシ

機能
======

* OpenID Connectによる認証
* HTTPだけではなくSSHへもプロキシ可
* バックエンドがNATの背後でもプロキシ可
* ブラウザによるユーザーの管理
* RBACによるユーザーの権限管理
* 専用オペレータにより Kubernetes へのデプロイが簡単

設定
=====

設定はYAMLファイルで行います。

4つの設定ファイルからなり、起動引数に設定したファイルに残りの3つのファイルのパスを定義します。

config.yaml
---------------

Listenするポートや使用する Identity Provider などを設定します。

`config_debug.yaml <./config_debug.yaml>`_ がローカルでの開発用の設定ファイルです。

次の3つのファイルは config.yaml でファイルパスを定義します。

proxies.yaml
---------------

バックエンドのサーバーを定義します。

設定例は `開発用のproxies.yaml <./proxies.yaml>`_ を参照してください。

roles.yaml
------------

ロールを定義します。

`roles.yaml <roles.yaml>`_ を参照してください。

rpc_permissions.yaml
-----------------------

RPCへの権限を定義します。

`rpc_permissions.yaml <./rpc_permissions.yaml>`_ を参照してください。

デプロイ
=========

オペレータを使って Kubernetes 上にデプロイすることが想定して作られています。

ベアメタル上へもデプロイすることは可能ですが、オペレータを利用し Kubernetes へデプロイすることを強くおすすめします。

エージェント
=============

バックエンドがNATの背後にいる場合はエージェントを利用することによってプロキシが可能になります。

エージェントはバックエンドと同じホストで実行するように設計されています。
またバックエンドとエージェントは1:1で対応するようにも設計されており、複数のバックエンドを利用する場合はバックエンドと同じ数のエージェントが必要です。
（直接プロキシできるエージェントが不要なバックエンドは除きます）

エージェントを利用する手順は以下のようになります。

1. バックエンドの設定を行う（ `agent: true` とする）
2. エージェント用の秘密鍵とCSRを作成する
   1. 秘密鍵を生成したいパスを指定して `heim-agent` を実行する。秘密鍵が存在しない場合は新規に作成しCSRも作成される
3. CSRをコピーしWeb UIから登録し、署名された証明書を発行する
4. 証明書をエージェントの引数に指定して実行する

エージェントが利用する秘密鍵は該当ホストの外に出す必要はありません。
該当ホストの外に送信しないように気をつけてください。

リファレンス
==============

BeyondCorp by Google.

* `BeyondCorp: A New Approach to Enterprise Security <https://ai.google/research/pubs/pub43231>`_
* `BeyondCorp: Design to Deployment at Google <https://ai.google/research/pubs/pub44860>`_
* `BeyondCorp: The Access Proxy <https://ai.google/research/pubs/pub45728>`_
* `Migrating to BeyondCorp: Maintainig Productivity While Improving Security <https://ai.google/research/pubs/pub46134>`_
* `BeyondCorp: The User Experience <https://ai.google/research/pubs/pub46366>`_
* `BeyondCorp 6: Building a Health Fleet <https://ai.google/research/pubs/pub47356>`_

LICENSE
===========

MIT

Author
=========

Fumihiro Ito <fmhrit@gmail.com>
