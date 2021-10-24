class User < ApplicationRecord
  
  #extende as opções do devise possibilitando a utilização do 
  #token (e email) para utilizar a API
  acts_as_token_authenticatable
  
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
end
